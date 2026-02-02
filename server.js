const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const chokidar = require('chokidar');
const zlib = require('zlib');
const UAParser = require('ua-parser-js');

// --- Configuration ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const NGINX_LOG_DIR = '/var/log/nginx';

// Serve static files
app.use(express.static(__dirname));

// Handle favicon.ico to prevent 404
app.get('/favicon.ico', (req, res) => res.status(204).end());

// Serve the main dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// --- Regex Patterns ---
const accessLogRegex = /^([\d\.]+) (.*?) (.*?) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"\s*$/;
const errorLogRegex = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[(.*?)\] (.*)$/;

// --- Helper Functions ---
const nginxMonths = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function parseAccessLogTimestamp(ts) {
    try {
        const match = ts.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2}) (.*)/);
        if (!match) return null;
        const [, day, month, year, time, zone] = match;
        const monthIndex = nginxMonths.indexOf(month);
        if (monthIndex === -1) return null;
        const isoString = `${year}-${(monthIndex + 1).toString().padStart(2, '0')}-${day}T${time}${zone}`;
        return new Date(isoString);
    } catch (e) { return null; }
}

function parseErrorLogTimestamp(ts) {
    try {
        const isoString = ts.replace(/\//g, '-').replace(' ', 'T');
        return new Date(isoString);
    } catch (e) { return null; }
}

function isDateInRange(logDate, startDate, endDate) {
    if (!logDate) return false;
    const start = startDate ? new Date(startDate) : null;
    if (start) start.setHours(0, 0, 0, 0);
    const end = endDate ? new Date(endDate) : null;
    if (end) end.setHours(23, 59, 59, 999);
    if (start && logDate < start) return false;
    if (end && logDate > end) return false;
    return true;
}

function getLogFiles(type) {
    try {
        const files = fs.readdirSync(NGINX_LOG_DIR);
        const logFiles = files.filter(file => file.startsWith(type === 'error' ? 'error.log' : 'access.log'));

        // Sort files: current log first, then .1, then .2.gz etc.
        return logFiles.sort((a, b) => {
            if (a === b) return 0;
            if (a === 'access.log' || a === 'error.log') return -1;
            if (b === 'access.log' || b === 'error.log') return 1;

            // Extract numbers for sorting
            const numA = parseInt(a.match(/\d+/) || 0);
            const numB = parseInt(b.match(/\d+/) || 0);
            return numA - numB;
        }).map(file => path.join(NGINX_LOG_DIR, file));
    } catch (e) {
        console.error('Error listing log files:', e);
        return [];
    }
}

async function processLogFile(filePath, callback) {
    const isGzip = filePath.endsWith('.gz');
    let fileStream = fs.createReadStream(filePath);

    if (isGzip) {
        fileStream = fileStream.pipe(zlib.createGunzip());
    }

    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    for await (const line of rl) {
        await callback(line);
    }
}

// --- Statistics Calculation ---
async function calculateStatistics() {
    const stats = {
        totalRequests: 0,
        todayRequests: 0,
        weekRequests: 0,
        errorCount: 0,
        todayErrors: 0,
        statusCodes: { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 },
        topIPs: {},
        topURLs: {},
        requestsPerHour: Array(24).fill(0),
        browsers: {},
        os: {},
        totalBytes: 0,
        errorLevels: { emerg: 0, alert: 0, crit: 0, error: 0, warn: 0, notice: 0, info: 0 },
        filesScanned: 0
    };

    // Process ALL access logs
    const accessFiles = getLogFiles('access');
    stats.filesScanned = accessFiles.length;

    for (const file of accessFiles) {
        try {
            await processLogFile(file, (line) => {
                const match = line.match(accessLogRegex);
                if (!match) return;

                stats.totalRequests++;
                const [, ip, , , timestampStr, request, status, bytesStr, , userAgent] = match;

                // Stats
                const bytes = parseInt(bytesStr) || 0;
                stats.totalBytes += bytes;

                const logDate = parseAccessLogTimestamp(timestampStr);
                if (logDate) {
                    const today = new Date();
                    const isToday = logDate.getDate() === today.getDate() &&
                        logDate.getMonth() === today.getMonth() &&
                        logDate.getFullYear() === today.getFullYear();

                    if (isToday) {
                        stats.todayRequests++;
                        stats.requestsPerHour[logDate.getHours()]++;
                    }
                }

                // Status
                const statusNum = parseInt(status);
                if (statusNum >= 200 && statusNum < 300) stats.statusCodes['2xx']++;
                else if (statusNum >= 300 && statusNum < 400) stats.statusCodes['3xx']++;
                else if (statusNum >= 400 && statusNum < 500) stats.statusCodes['4xx']++;
                else if (statusNum >= 500) stats.statusCodes['5xx']++;

                // Top Lists
                stats.topIPs[ip] = (stats.topIPs[ip] || 0) + 1;
                const url = request.split(' ')[1]?.split('?')[0];
                if (url) stats.topURLs[url] = (stats.topURLs[url] || 0) + 1;

                // User Agent
                if (userAgent && userAgent !== '-') {
                    const ua = UAParser(userAgent);
                    const browser = ua.browser.name || 'Unknown';
                    const os = ua.os.name || 'Unknown';
                    stats.browsers[browser] = (stats.browsers[browser] || 0) + 1;
                    stats.os[os] = (stats.os[os] || 0) + 1;
                }
            });
        } catch (e) {
            console.error(`Error reading ${file}:`, e.message);
        }
    }

    // Process ALL error logs
    const errorFiles = getLogFiles('error');
    for (const file of errorFiles) {
        try {
            await processLogFile(file, (line) => {
                const match = line.match(errorLogRegex);
                if (!match) return;

                stats.errorCount++;
                const [, timestamp, level] = match;

                const logDate = parseErrorLogTimestamp(timestamp);
                if (logDate) {
                    const today = new Date();
                    if (logDate.getDate() === today.getDate() &&
                        logDate.getMonth() === today.getMonth() &&
                        logDate.getFullYear() === today.getFullYear()) {
                        stats.todayErrors++;
                    }
                }

                const lvl = level.toLowerCase();
                if (stats.errorLevels.hasOwnProperty(lvl)) {
                    stats.errorLevels[lvl]++;
                }
            });
        } catch (e) {
            console.error(`Error reading ${file}:`, e.message);
        }
    }

    // Format Top 10s
    const formatTop = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, 10);

    return {
        ...stats,
        topIPs: formatTop(stats.topIPs),
        topURLs: formatTop(stats.topURLs),
        topBrowsers: formatTop(stats.browsers),
        topOS: formatTop(stats.os),
        errorRate: stats.totalRequests ? ((stats.statusCodes['4xx'] + stats.statusCodes['5xx']) / stats.totalRequests * 100).toFixed(2) : 0
    };
}

// --- File Watcher ---
function setupFileWatcher() {
    const mainAccess = path.join(NGINX_LOG_DIR, 'access.log');
    const mainError = path.join(NGINX_LOG_DIR, 'error.log');
    let sizes = {};

    try {
        if (fs.existsSync(mainAccess)) sizes[mainAccess] = fs.statSync(mainAccess).size;
        if (fs.existsSync(mainError)) sizes[mainError] = fs.statSync(mainError).size;
        console.log('Initial log sizes:', sizes);
    } catch (e) { console.error('Error getting initial sizes:', e); }

    const watcher = chokidar.watch([mainAccess, mainError], {
        persistent: true,
        usePolling: true,
        interval: 500, // Faster polling
        awaitWriteFinish: { stabilityThreshold: 200 } // Wait for write to finish
    });

    watcher.on('ready', () => console.log('File watcher is ready and scanning...'));

    watcher.on('change', async (filePath) => {
        try {
            console.log(`File change detected: ${filePath}`);
            const stat = fs.statSync(filePath);
            const prevSize = sizes[filePath] || 0;

            console.log(`Size check - Old: ${prevSize}, New: ${stat.size}`);

            if (stat.size > prevSize) {
                const stream = fs.createReadStream(filePath, { start: prevSize, end: stat.size });
                const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
                const newLogs = [];

                for await (const line of rl) {
                    if (!line.trim()) continue;
                    const isAccess = filePath.includes('access.log');

                    if (isAccess) {
                        const match = line.match(accessLogRegex);
                        if (match) {
                            const ua = UAParser(match[9]);
                            newLogs.push({
                                type: 'access',
                                ip: match[1],
                                timestampStr: match[4],
                                request: match[5],
                                status: match[6],
                                bytes: match[7],
                                referer: match[8],
                                userAgent: match[9],
                                browser: ua.browser.name,
                                os: ua.os.name,
                                raw: line
                            });
                        }
                    } else {
                        const match = line.match(errorLogRegex);
                        if (match) {
                            newLogs.push({
                                type: 'error',
                                timestamp: match[1],
                                level: match[2],
                                message: match[3],
                                raw: line
                            });
                        }
                    }
                }

                if (newLogs.length) {
                    console.log(`Emitting ${newLogs.length} new logs via WebSocket`);
                    io.emit('newLogs', newLogs);
                }
                sizes[filePath] = stat.size;
            } else if (stat.size < prevSize) {
                // Log rotated?
                console.log('Log file size decreased (rotation detected). Resetting size.');
                sizes[filePath] = stat.size;
            }
        } catch (e) { console.error('Watcher error:', e); }
    });
}

// --- API Endpoints ---
app.get('/api/stats', async (req, res) => {
    const stats = await calculateStatistics();
    res.json(stats);
});

app.get('/api/access-logs', async (req, res) => {
    const { page = 1, limit = 50, search = '', ip = '', status = '', startDate, endDate } = req.query;
    const searchLower = search.toLowerCase();
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const numLimit = parseInt(limit);

    // We only read the first N matching logs to avoid OOM on huge history
    // For pagination, we'll need to read potentially everything. 
    // Optimization: Stream and count, only storing current page lines

    // NOTE: Reading ALL history for pagination every time is slow. 
    // In a prod app, we'd database this. For now, we'll limit historical search to reasonable bounds
    // or just scan aggressively.

    const logs = [];
    let count = 0;
    let matchCount = 0;

    const files = getLogFiles('access'); // access.log, access.log.1, ...

    // Strategy: We want the NEWEST logs first.
    // So we iterate files in order: access.log (newest), then log.1, etc.
    // And for each file, we read it. BUT reading a file line-by-line gives oldest-first for that file.
    // So for the current log file, we might want to read-reverse, but that's hard with GZIP.
    // Simple approach: Read all files, filter, store matches (up to a safe limit), then slice.

    const MAX_MEMORY_LOGS = 10000; // Limit in-memory results for safety

    outer: for (const file of files) {
        try {
            // We need to collect lines for this file to reverse them if we want true reverse chron order across files?
            // Actually, standard rotation: access.log has [T0...Tnow], access.log.1 has [T-1...T0].
            // So if we read access.log from end-to-start, then access.log.1 from end-to-start, we are perfect.
            // Reading streams backwards is tricky.
            // Alternative: Read file forward, store in array, reverse array.

            const fileLogs = [];
            await processLogFile(file, (line) => {
                fileLogs.push(line);
            });

            // Reverse this file's logs to get newest first
            fileLogs.reverse();

            for (const line of fileLogs) {
                const lineLower = line.toLowerCase();
                if (searchLower && !lineLower.includes(searchLower)) continue;

                const match = line.match(accessLogRegex);
                if (!match) continue;

                const log = {
                    ip: match[1],
                    timestampStr: match[4],
                    request: match[5],
                    status: match[6],
                    bytes: match[7],
                    referer: match[8],
                    userAgent: match[9]
                };

                // Filter IP
                if (ip && !log.ip.includes(ip)) continue;
                // Filter Status
                if (status && !log.status.startsWith(status.replace('xx', ''))) continue;

                // Date Filter
                if (startDate || endDate) {
                    const d = parseAccessLogTimestamp(log.timestampStr);
                    if (!isDateInRange(d, startDate, endDate)) continue;
                }

                matchCount++;

                // Optimization: Only store logs if they fall within the requested page
                if (matchCount > offset && logs.length < numLimit) {
                    // Parse UA details for the displayed logs
                    const ua = UAParser(log.userAgent);
                    log.browser = ua.browser.name;
                    log.os = ua.os.name;
                    logs.push(log);
                }

                // Hard limit query scan to avoid timeouts on massive logs
                if (matchCount > offset + numLimit + 10000) break outer;
            }
        } catch (e) { }
    }

    res.json({
        matchingCount: matchCount, // This might be an approximation if we broke early
        page: parseInt(page),
        totalPages: Math.ceil(matchCount / numLimit),
        logs: logs
    });
});

app.get('/api/error-logs', async (req, res) => {
    // Similar logic for error logs
    const { page = 1, limit = 50, search = '' } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const numLimit = parseInt(limit);
    const searchLower = search.toLowerCase();

    const logs = [];
    let matchCount = 0;
    const files = getLogFiles('error');

    outer: for (const file of files) {
        const fileLines = [];
        await processLogFile(file, l => fileLines.push(l));
        fileLines.reverse();

        for (const line of fileLines) {
            if (searchLower && !line.toLowerCase().includes(searchLower)) continue;
            const match = line.match(errorLogRegex);
            if (!match) continue;

            matchCount++;
            if (matchCount > offset && logs.length < numLimit) {
                logs.push({
                    timestamp: match[1],
                    level: match[2],
                    message: match[3]
                });
            }
        }
    }

    res.json({
        matchingCount: matchCount,
        page: parseInt(page),
        totalPages: Math.ceil(matchCount / numLimit),
        logs: logs
    });
});

app.get('/api/tail', async (req, res) => {
    // Just tail the main file
    const { type = 'access', lines = 100 } = req.query;
    const filePath = path.join(NGINX_LOG_DIR, type === 'error' ? 'error.log' : 'access.log');
    if (!fs.existsSync(filePath)) return res.json({ logs: [] });

    const fileLines = [];
    await processLogFile(filePath, l => fileLines.push(l));
    const tailLines = fileLines.slice(-parseInt(lines));

    const parsed = tailLines.map(line => {
        if (type === 'access') {
            const m = line.match(accessLogRegex);
            if (m) {
                const ua = UAParser(m[9]);
                return { type, ip: m[1], timestampStr: m[4], request: m[5], status: m[6], ua: m[9], browser: ua.browser.name, raw: line };
            }
        } else {
            const m = line.match(errorLogRegex);
            if (m) return { type, timestamp: m[1], level: m[2], message: m[3], raw: line };
        }
    }).filter(x => x);

    res.json({ logs: parsed });
});


server.listen(PORT, () => {
    console.log(`🚀 Professional Log Server running on ${PORT}`);
    setupFileWatcher();
});
