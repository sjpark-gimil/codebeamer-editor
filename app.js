require('dotenv').config();
const express = require('express');
const axios = require('axios');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const FormData = require('form-data');
const crypto = require('crypto');

const defaults = {
    cbApiUrl: process.env.CB_BASE_URL || 'http://192.168.0.81:8080/cb',
    sessionSecret: process.env.SESSION_SECRET || 'default-secret',
};

function normalizePath(filePath) {
    if (!filePath) return '';

    let normalized = filePath.replace(/\\/g, '/');
    if (/^[a-zA-Z]:/.test(normalized) && normalized.charAt(2) !== '/') {
        normalized = normalized.charAt(0) + ':/' + normalized.substring(2);
    }    
    return normalized;
}

let reportPaths = { vectorcast: '' };

const app = express();
const PORT = 3001;
const HOST = '0.0.0.0';
const corsOptions = { 
    origin: '*', 
    methods: ['GET', 'PUT', 'POST', 'DELETE'], 
    allowedHeaders: ['Content-Type', 'Authorization', 'accept'],
    credentials: true
};

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cors(corsOptions));
app.use(session({  
    secret: defaults.sessionSecret,  
    resave: false,  
    saveUninitialized: false,
    cookie: {
        secure: false, 
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 
    }
}));

console.log('Starting application in normal mode');
loadSettingsFromLocalStorage();
startApp();

function startApp() {
    try {
        const server = app.listen(PORT, HOST, () => {
            console.log(`Server running on port ${PORT} on ${HOST} (all interfaces)`);
        }).on('error', (err) => {
            console.error('Server error:', err.message);
            console.log('Trying to restart server in 10 seconds...');
            setTimeout(() => {
                startApp();
            }, 10000);
        });
        
        return server;
    } catch (error) {
        console.error('Error starting server:', error);
        console.log('Trying to restart server in 10 seconds...');
        setTimeout(() => {
            startApp();
        }, 10000);
    }
}

function requireAuth(req, res, next) {
    if (req.session && req.session.auth) {
        next();
    } else {
        res.redirect('/login');
    }
}

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) { 
        return res.render('login', { 
            error: 'Username and password are required',
            serverUrl: defaults.cbApiUrl
        }); 
    }

    const auth = Buffer.from(`${username}:${password}`).toString('base64');
    req.session.auth = auth;
    req.session.username = username;
    req.session.save((err) => {
        if (err) {
            console.error('Session save error:', err);
            return res.render('login', { 
                error: 'Session error occurred',
                serverUrl: defaults.cbApiUrl
            });
        }
        res.redirect('/');
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) { console.error('Error destroying session:', err); }
        res.redirect('/login');
    });
});

app.get('/api/debug/ping', async (req, res) => {
    try {
        const pingUrl = `${defaults.cbApiUrl}/ping`;
        console.log('Pinging CodeBeamer at:', pingUrl);
        
        const response = await axios.get(pingUrl, {
            timeout: 5000,
            validateStatus: function (status) {
                return status < 500;
            }
        });

        res.json({
            success: true,
            url: pingUrl,
            status: response.status,
            message: 'CodeBeamer is reachable'
        });
    } catch (error) {
        res.json({
            success: false,
            url: pingUrl,
            error: error.message,
            message: 'CodeBeamer is not reachable'
        });
    }
});

app.get('/api/debug/codebeamer-test', requireAuth, async (req, res) => {
    const results = [];
    
    const testUrls = [
        `${defaults.cbApiUrl}/api/v3/projects`,
        `${defaults.cbApiUrl}/api/projects`,
        `${defaults.cbApiUrl}/projects`,
        `${defaults.cbApiUrl}/cb/api/v3/projects`,
        `${defaults.cbApiUrl}/cb/api/v2/projects`
    ];
    
    for (const testUrl of testUrls) {
        try {
            console.log('Testing CodeBeamer connectivity to:', testUrl);
            
            const response = await axios.get(testUrl, {
                headers: {
                    'Authorization': `Basic ${req.session.auth}`,
                    'Content-Type': 'application/json',
                    'accept': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                timeout: 5000,
                validateStatus: function (status) {
                    return status < 500;
                }
            });

            results.push({
                url: testUrl,
                success: true,
                status: response.status,
                dataLength: response.data ? (Array.isArray(response.data) ? response.data.length : Object.keys(response.data).length) : 0
            });
            
            if (response.status === 200) {
                break;
            }
        } catch (error) {
            results.push({
                url: testUrl,
                success: false,
                error: error.message,
                status: error.response ? error.response.status : 'No response'
            });
        }
    }
    
    res.json({
        auth: req.session.auth,
        username: req.session.username,
        baseUrl: defaults.cbApiUrl,
        results: results
    });
});

app.get('/', requireAuth, (req, res) => {
    res.render('list', {
        currentPath: '/',
        username: req.session.username || '',
        vectorcastPath: reportPaths.vectorcast || '',
        serverUrl: defaults.cbApiUrl,
        cbBaseUrl: process.env.CB_BASE_URL || 'http://192.168.0.81:8080/cb'
    });
});

app.post('/settings', (req, res) => {
    try {
        const { reportPaths: newPaths, serverUrl } = req.body;
        
        if (newPaths) {
            if (newPaths.vectorcast) reportPaths.vectorcast = normalizePath(newPaths.vectorcast);
        }
        
        if (serverUrl) defaults.cbApiUrl = serverUrl;
  
        const settings = {
            reportPaths: { ...reportPaths },
            serverUrl: defaults.cbApiUrl
        };
        
        fs.writeFileSync(path.join(__dirname, 'settings.json'), JSON.stringify(settings, null, 2));
        res.status(200).json({ success: true, message: 'Settings updated successfully' });
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ success: false, message: 'Failed to update settings' });
    }
});

function loadSettingsFromLocalStorage() {
    try {
        const settings = JSON.parse(fs.readFileSync(path.join(__dirname, 'settings.json'), 'utf8'));
        if (settings.reportPaths) {
            for (const [key, value] of Object.entries(settings.reportPaths)) {
                if (value) reportPaths[key] = normalizePath(value);
            }
        }
        if (settings.serverUrl) {
            console.log('Loading serverUrl from settings:', settings.serverUrl);
            defaults.cbApiUrl = settings.serverUrl;
            console.log('defaults.cbApiUrl set to:', defaults.cbApiUrl);
        }
    } catch (error) {
        console.log('Error loading settings:', error.message);
    }
}

app.get('/settings/paths', (req, res) => {
    res.json({
        reportPaths: reportPaths,
        serverUrl: defaults.cbApiUrl
    });
});

app.get('/report-settings', requireAuth, (req, res) => {
    res.render('report-settings', {
        currentPath: '/report-settings',
        username: req.session.username || '',
        vectorcastPath: reportPaths.vectorcast || '',
        serverUrl: defaults.cbApiUrl,
        trackerUrl: process.env.CB_BASE_URL || 'http://192.168.0.81:8080/cb'
    });
});

function getErrorMessage(status) {
    const errorMessages = {
        400: "잘못된 요청입니다(Item ID 또는 리포트 파일이 없습니다)",
        401: "인가되지 않은 사용자입니다",
        403: "접근 권한이 없습니다",
        404: "요청한 리소스를 찾을 수 없습니다",
        409: "리소스 충돌이 발생했습니다",
        500: "서버 내부 오류가 발생했습니다",
        503: "서비스가 일시적으로 사용할 수 없습니다"
    };
    return errorMessages[status] || `서버 오류가 발생했습니다 (${status})`;
}

async function uploadAttachmentToCodeBeamer(itemId, fileName, fileBuffer, auth) {
    try {
        console.log(`Starting attachment upload for item ${itemId}, file: ${fileName}`);
        console.log(`File buffer size: ${fileBuffer.length} bytes`);
        
        const formData = new FormData();
        
        // Determine content type based on file extension
        const getContentType = (filename) => {
            const ext = filename.toLowerCase().split('.').pop();
            const contentTypes = {
                'pdf': 'application/pdf',
                'doc': 'application/msword',
                'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'xls': 'application/vnd.ms-excel',
                'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'ppt': 'application/vnd.ms-powerpoint',
                'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                'html': 'text/html',
                'htm': 'text/html',
                'txt': 'text/plain',
                'csv': 'text/csv',
                'json': 'application/json',
                'xml': 'application/xml',
                'png': 'image/png',
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'gif': 'image/gif',
                'zip': 'application/zip',
                'rar': 'application/x-rar-compressed'
            };
            return contentTypes[ext] || 'application/octet-stream';
        };
        
        const contentType = getContentType(fileName);
        
        formData.append('attachments', fileBuffer, {
            filename: fileName,
            contentType: contentType
        });

        const attachmentUrl = `${defaults.cbApiUrl}/api/v3/items/${itemId}/attachments`;
        console.log(`Attachment upload URL: ${attachmentUrl}`);
        
        const response = await axios.post(attachmentUrl, formData, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Accept': 'application/json',
                ...formData.getHeaders()
            },
            validateStatus: status => status < 500
        });

        console.log(`Attachment upload response status: ${response.status}`);
        console.log(`Attachment upload response data:`, response.data);

        if (response.status >= 400) {
            console.error(`Attachment upload failed with status ${response.status}:`, response.data);
            throw new Error(`Attachment upload failed: ${getErrorMessage(response.status)}`);
        }

        console.log(`Attachment upload successful for item ${itemId}`);
        return {
            success: true,
            attachmentId: response.data[0]?.id,
            message: 'File uploaded successfully'
        };
    } catch (error) {
        console.error('Error uploading attachment:', error.message);
        if (error.response) {
            console.error('Error response status:', error.response.status);
            console.error('Error response data:', error.response.data);
        }
        return {
            success: false,
            error: error.message || 'File upload failed'
        };
    }
}

app.post('/api/codebeamer/upload-report', requireAuth, async (req, res) => {
    if (!req.session || !req.session.auth) {
        return res.status(401).json({ error: 'Unauthorized user' });
    }

    try {
        const { fileName, fileContent, itemIds } = req.body;
        
        if (!fileName || !fileContent || !itemIds || !Array.isArray(itemIds) || itemIds.length === 0) {
            return res.status(400).json({ error: 'Missing required fields: fileName, fileContent, and itemIds array' });
        }

        const results = [];
        
        for (let i = 0; i < itemIds.length; i++) {
            const itemId = itemIds[i];
            
            console.log(`Processing upload ${i + 1}/${itemIds.length} for item ${itemId}`);
            
            try {
                const fileBuffer = Buffer.from(fileContent, 'base64');
                
                const attachmentResult = await uploadAttachmentToCodeBeamer(
                    itemId, 
                    fileName, 
                    fileBuffer, 
                    req.session.auth
                );
                
                if (attachmentResult.success) {
                    results.push({
                        itemId: itemId,
                        success: true,
                        message: 'File uploaded successfully',
                        attachmentId: attachmentResult.attachmentId
                    });
                } else {
                    results.push({
                        itemId: itemId,
                        success: false,
                        error: attachmentResult.error
                    });
                }

                if (i < itemIds.length - 1) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
                
            } catch (error) {
                results.push({
                    itemId: itemId,
                    success: false,
                    error: error.message
                });
            }
        }

        const successCount = results.filter(r => r.success).length;
        const failureCount = results.length - successCount;

        res.json({
            totalItems: itemIds.length,
            successCount,
            failureCount,
            results
        });

    } catch (error) {
        console.error('Error in generic report upload:', error);
        res.status(500).json({ error: 'Internal server error: ' + error.message });
    }
});

app.get('/api/codebeamer/projects', requireAuth, async (req, res) => {
    if (!req.session || !req.session.auth) {
        return res.status(401).json({ error: '인가되지 않은 사용자입니다' });
    }

    try {
        const codebeamerUrl = `${defaults.cbApiUrl}/api/v3/projects`;
        console.log('Fetching projects from:', codebeamerUrl);
        console.log('Using auth:', req.session.auth);
        console.log('Username:', req.session.username);
        
        const response = await axios.get(codebeamerUrl, {
            headers: {
                'Authorization': `Basic ${req.session.auth}`,
                'Content-Type': 'application/json',
                'accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout: 10000,
            validateStatus: function (status) {
                return status < 500; // Resolve only if the status code is less than 500
            }
        });

        console.log('Response status:', response.status);
        console.log('Response headers:', response.headers);
        
        if (response.status === 401) {
            console.error('Authentication failed - 401 Unauthorized');
            return res.status(401).json({ 
                error: 'Authentication failed with external CodeBeamer instance',
                details: 'Please check if the external IP requires different authentication or API version'
            });
        }

        res.json(response.data);
    } catch (error) {
        console.error('Error fetching projects:', error.message);
        if (error.response) {
            console.error('Error response status:', error.response.status);
            console.error('Error response data:', error.response.data);
        }
        res.status(500).json({ error: 'Failed to fetch projects: ' + error.message });
    }
});

app.get('/api/codebeamer/projects/:projectId/trackers', requireAuth, async (req, res) => {
    if (!req.session || !req.session.auth) {
        return res.status(401).json({ error: '인가되지 않은 사용자입니다' });
    }

    try {
        const { projectId } = req.params;
        const codebeamerUrl = `${defaults.cbApiUrl}/api/v3/projects/${projectId}/trackers`;
        
        const response = await axios.get(codebeamerUrl, {
            headers: {
                'Authorization': `Basic ${req.session.auth}`,
                'Content-Type': 'application/json',
                'accept': 'application/json'
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error('Error fetching trackers:', error.message);
        res.status(500).json({ error: 'Failed to fetch trackers' });
    }
});

app.get('/api/codebeamer/trackers/:trackerId/items', requireAuth, async (req, res) => {
    if (!req.session || !req.session.auth) {
        return res.status(401).json({ error: '인가되지 않은 사용자입니다' });
    }

    try {
        const { trackerId } = req.params;
        const codebeamerUrl = `${defaults.cbApiUrl}/api/v3/trackers/${trackerId}/items`;
        
        const response = await axios.get(codebeamerUrl, {
            headers: {
                'Authorization': `Basic ${req.session.auth}`,
                'Content-Type': 'application/json',
                'accept': 'application/json'
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error('Error fetching items:', error.message);
        res.status(500).json({ error: 'Failed to fetch items' });
    }
});

