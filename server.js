const express = require('express');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const app = express();
const PORT = 3000;
const ACCESS_LOG_PATH = path.join(__dirname, 'access.log');
const ERROR_LOG_PATH = path.join(__dirname, 'error.log'); // <-- Reads your new file

// --- Regex Patterns ---
const accessLogRegex = /^([\d\.]+) (.*?) (.*?) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"\s*$/;
// Regex for: 2025/09/22 18:29:29 [emerg] 1048#4384: message
const errorLogRegex = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[(.*?)\] (.*)$/; // <-- This matches your error.log

// --- Timestamp Helper Functions ---

const nginxMonths = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/**
 * Parses Nginx access.log timestamp (e.g., "15/Nov/2025:12:00:00 +0000")
 */
function parseAccessLogTimestamp(ts) {
    try {
        const [, day, month, year, time, zone] = ts.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2}) (.*)/);
        const monthIndex = nginxMonths.indexOf(month);
        if (monthIndex === -1) return null;
        
        const isoString = `${year}-${(monthIndex + 1).toString().padStart(2, '0')}-${day}T${time}${zone}`;
        return new Date(isoString);
    } catch (e) {
        console.warn(`Could not parse access log timestamp: ${ts}`);
        return null;
    }
}

/**
 * Parses Nginx error.log timestamp (e.g., "2025/11/15 12:00:00")
 */
function parseErrorLogTimestamp(ts) {
    try {
        const isoString = ts.replace(' ', 'T');
        return new Date(isoString);
    } catch (e) {
        console.warn(`Could not parse error log timestamp: ${ts}`);
        return null;
    }
}

/**
 * Checks if a log date is within the specified date range.
 */
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


// --- API Endpoints ---

// Serve the log.html file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'log.html'));
});

/**
 * API endpoint for ACCESS logs
 */
app.get('/api/access-logs', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 50,
            search = '',
            ip = '',
            status = '',
            startDate = '',
            endDate = ''
        } = req.query;

        const searchLower = search.toLowerCase();
        const ipLower = ip.toLowerCase();
        const statusLower = status.toLowerCase();

        const offset = (parseInt(page) - 1) * parseInt(limit);
        const numLimit = parseInt(limit);

        const paginatedLogs = [];
        let matchingCount = 0;

        // Check if access.log exists
        if (!fs.existsSync(ACCESS_LOG_PATH)) {
            return res.json({ matchingCount: 0, page: 1, totalPages: 0, logs: [] });
        }

        const fileStream = fs.createReadStream(ACCESS_LOG_PATH);
        const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

        for await (const line of rl) {
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
                userAgent: match[9],
                raw: lineLower
            };

            if (startDate || endDate) {
                const logDate = parseAccessLogTimestamp(log.timestampStr);
                if (!isDateInRange(logDate, startDate, endDate)) {
                    continue;
                }
            }
            
            if (ipLower && !log.ip.toLowerCase().includes(ipLower)) continue;
            
            if (statusLower) {
                if (statusLower.endsWith('xx')) {
                    const prefix = statusLower.charAt(0);
                    if (!log.status.startsWith(prefix)) continue;
                } else {
                    if (!log.status.includes(statusLower)) continue;
                }
            }

            matchingCount++;
            if (matchingCount > offset && paginatedLogs.length < numLimit) {
                paginatedLogs.push(log);
            }
        }

        res.json({
            matchingCount,
            page: parseInt(page),
            totalPages: Math.ceil(matchingCount / numLimit),
            logs: paginatedLogs
        });

    } catch (error) {
        console.error('Error reading access log:', error);
        res.status(500).json({ error: 'Failed to read access.log.' });
    }
});

/**
 * API endpoint for ERROR logs
 */
app.get('/api/error-logs', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 50,
            search = '',
            level = '',
            startDate = '',
            endDate = ''
        } = req.query;

        const searchLower = search.toLowerCase();
        const levelLower = level.toLowerCase();

        const offset = (parseInt(page) - 1) * parseInt(limit);
        const numLimit = parseInt(limit);

        const paginatedLogs = [];
        let matchingCount = 0;

        // Check if error.log exists
        if (!fs.existsSync(ERROR_LOG_PATH)) {
            return res.json({ matchingCount: 0, page: 1, totalPages: 0, logs: [] });
        }

        const fileStream = fs.createReadStream(ERROR_LOG_PATH);
        const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

        for await (const line of rl) {
            const lineLower = line.toLowerCase();
            if (searchLower && !lineLower.includes(searchLower)) continue;

            const match = line.match(errorLogRegex);
            if (!match) continue;

            const log = {
                timestamp: match[1],
                level: match[2],
                message: match[3],
                raw: lineLower
            };

            if (startDate || endDate) {
                const logDate = parseErrorLogTimestamp(log.timestamp);
                if (!isDateInRange(logDate, startDate, endDate)) {
                    continue;
                }
            }

            if (levelLower && !log.level.toLowerCase().includes(levelLower)) continue;

            matchingCount++;
            if (matchingCount > offset && paginatedLogs.length < numLimit) {
                paginatedLogs.push(log);
            }
        }

        res.json({
            matchingCount,
            page: parseInt(page),
            totalPages: Math.ceil(matchingCount / numLimit),
            logs: paginatedLogs
        });

    } catch (error) {
        console.error('Error reading error log:', error);
        res.status(500).json({ error: 'Failed to read error.log.' });
    }
});


app.listen(PORT, () => {
    console.log(`Log viewer server running at http://localhost:${PORT}`);
});