const express = require('express');
const axios = require('axios');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const FormData = require('form-data');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createProxyMiddleware } = require('http-proxy-middleware');

const defaults = {
    cbApiUrl: 'http://codebeamer.mdsit.co.kr:3008',
    cbWebUrl: 'http://codebeamer.mdsit.co.kr:3008',
    sessionSecret: 'default-secret',
};

// JWT Configuration for CodeBeamer Authentication
const CB_JWT_SECRET = "CB-ENCRYPTED-D4-6E-6C-91-E4-56-4E-40-77-E2-9A-7A-E5-B7-5E-92-73-44-29-56-74-4C-B9-ED-86-A8-8-76-2-68-6E-A5-44-8E-1F-AD-DD-85-EF-E7-8E-B1-F9-8D-C1-46-D3-46-A6-7D-E4-B5-C8-2-4A-B9-18-BB-BA-2-92-AA-AE-3F-4E-DD-29-18-4B-11-85-C9-E7-0-69-58-B-A7-91-F4-CB-F3-10-43-9E-D9-E-B9-D0-0-1C-1F-9A-EF-C7-EB-0-6F-2E-37-3D-A1-7A-56-DB-6E-CB-3B-6D-C6-1C-3E-F1-A8-F8-BD-4A-BE-79-8-EE-A4-9E-7B-D1-97-8-D6-6F-F8-9F-55-29-56-5C-7D-F6-86-71-9A-6E-7D-2E-DC-DC-55-98-C4-6B-CF-25-5E-48-7E-32-71-61-D0-3F-85-6F-82-95-8E-A6-39-13-A7-B-4B-2F-A-EC-1F-B4-50-11-32-74-5C-59-30-B6-7-6A-B5-C2-9-A8-55-39-AE-63-A3-FF-F-C0-F0-A1-84-BF-20-FB-1B-35-72-D7-E8-3F-BB-56-57-C1-97-EA-EE-7A-85-F5-2E-1E-AC-1-25-49-F4-23-DB-25-3C-CC-0-87-62-7F-64-49-53-F0-90-26-CB-F7-45-1E-77-47-E0-F3-CC-39-C0-A2-74-4C-AA-1D-C6-8D-15-AF-AE-B4-29";
const CB_TOKEN_VALID_MINUTES = 262800; // 6 months
const CB_TOKEN_RENEW_TIMEFRAME = 30; // 30 minutes
const userCredentials = { 
    'vectorCAST': { username: 'vectorCAST', password: '1234', role: 'user' },
    'mds': { username: 'mds', password: '1234', role: 'user' },
    'sejin.park': { username: 'sejin.park', password: '1234', role: 'admin' }
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

// JWT Functions for CodeBeamer Authentication  
const generateCodebeamerJWT = (username = 'vectorCAST') => {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + (CB_TOKEN_VALID_MINUTES * 60);
    
    const payload = {
        iss: 'codeBeamer',
        name: username,
        exp: expiresAt,
        type: 'access',
        iat: now
    };
    
    const token = jwt.sign(payload, CB_JWT_SECRET, { algorithm: 'HS256' });
    return token;
};

const isJWTValid = (token) => {
    try {
        const decoded = jwt.verify(token, CB_JWT_SECRET);
        return decoded.exp > Math.floor(Date.now() / 1000);
    } catch (error) {
        return false;
    }
};

const validateAdminSession = (token) => {
    try {
        if (!token) return false;
        
        const decoded = jwt.verify(token, CB_JWT_SECRET);
        const isValid = decoded.exp > Math.floor(Date.now() / 1000);
        const isAdmin = decoded.name === 'sejin.park';
        
        return isValid && isAdmin;
    } catch (error) {
        return false;
    }
};

const performCodebeamerLogin = async (username = 'sejin.park') => {
    try {
        const userCreds = userCredentials[username];
        if (!userCreds) {
            return { success: false, error: 'User not found' };
        }

        const loginPageResponse = await axios.get('http://codebeamer.mdsit.co.kr:3008/login.spr');
        const csrfMatch = loginPageResponse.data.match(/name="_csrf" value="([^"]+)"/);
        const csrfToken = csrfMatch ? csrfMatch[1] : '';
        const loginResponse = await axios.post('http://codebeamer.mdsit.co.kr:3008/login.spr', 
            `user=${userCreds.username}&password=${userCreds.password}&_csrf=${csrfToken}`,
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                maxRedirects: 0,
                validateStatus: (status) => status < 400
            }
        );

        const cookies = loginResponse.headers['set-cookie'];
        return { success: true, cookies, csrfToken, username: userCreds.username };
        
    } catch (error) {
        console.error('Codebeamer login error:', error.message);
        return { success: false, error: error.message };
    }
};

const app = express();
const PORT = 3001;
const HOST = '0.0.0.0';
const corsOptions = { 
    origin: '*', 
    methods: ['GET', 'PUT', 'POST', 'DELETE'], 
    allowedHeaders: ['Content-Type', 'Authorization', 'accept'],
    credentials: true
};

// Hardcoded credentials for temporary auto-login
const HARDCODED_USERNAME = 'vectorCAST';
const HARDCODED_PASSWORD = '1234';
const BYPASS_LOGIN = true; // Set to false to re-enable normal login


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
    } else if (BYPASS_LOGIN) {
        // Auto-authenticate with hardcoded credentials
        const auth = Buffer.from(`${HARDCODED_USERNAME}:${HARDCODED_PASSWORD}`).toString('base64');
        req.session.auth = auth;
        req.session.username = HARDCODED_USERNAME;
        next();
    } else {
        res.redirect('/login');
    }
}

app.get('/login', (req, res) => {
    if (BYPASS_LOGIN) {
        // Auto-redirect to main page if bypass is enabled
        const auth = Buffer.from(`${HARDCODED_USERNAME}:${HARDCODED_PASSWORD}`).toString('base64');
        req.session.auth = auth;
        req.session.username = HARDCODED_USERNAME;
        req.session.save(() => {
            res.redirect('/');
        });
    } else {
        res.render('login', { error: null });
    }
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

app.get('/', requireAuth, (req, res) => {
    res.render('list', {
        currentPath: '/',
        username: req.session.username || HARDCODED_USERNAME,
        vectorcastPath: reportPaths.vectorcast || '',
        serverUrl: defaults.cbApiUrl
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
        serverUrl: defaults.cbApiUrl
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
        
        // Append the file to form data
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

// New generic report upload endpoint
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
                // Convert base64 back to buffer
                const fileBuffer = Buffer.from(fileContent, 'base64');
                
                // Upload attachment to CodeBeamer
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

                // Add delay to avoid rate limiting for multiple uploads
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
        
        const response = await axios.get(codebeamerUrl, {
            headers: {
                'Authorization': `Basic ${req.session.auth}`,
                'Content-Type': 'application/json',
                'accept': 'application/json'
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error('Error fetching projects:', error.message);
        res.status(500).json({ error: 'Failed to fetch projects' });
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

app.get('/api/auth/jwt', (req, res) => {
    try {
        const adminToken = req.headers.authorization?.replace('Bearer ', '') || req.query.adminToken;
        
        if (!adminToken) {
            return res.status(401).json({
                success: false,
                error: 'Admin token is required',
                message: 'Please provide admin session token (sejin.park)'
            });
        }
        
        const isAdminValid = validateAdminSession(adminToken);
        
        if (!isAdminValid) {
            return res.status(403).json({
                success: false,
                error: 'Invalid or expired admin session',
                message: 'Admin session (sejin.park) must be valid and active'
            });
        }
        
        const jwtToken = generateCodebeamerJWT('vectorCAST');
        res.json({
            success: true,
            token: jwtToken,
            valid: isJWTValid(jwtToken),
            expiry: new Date((Math.floor(Date.now() / 1000) + (CB_TOKEN_VALID_MINUTES * 60)) * 1000).toISOString(),
            codebeamerUrl: 'http://codebeamer.mdsit.co.kr:3008',
            user: 'vectorCAST',
            userRole: 'user',
            adminValidated: true
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/api/auth/validate-admin', (req, res) => {
    try {
        const adminToken = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
        
        if (!adminToken) {
            return res.status(400).json({
                success: false,
                error: 'Admin token is required'
            });
        }
        
        const isValid = validateAdminSession(adminToken);
        
        if (isValid) {
            const decoded = jwt.verify(adminToken, CB_JWT_SECRET);
            res.json({
                success: true,
                valid: true,
                user: decoded.name,
                role: 'admin',
                exp: decoded.exp,
                expDate: new Date(decoded.exp * 1000).toISOString()
            });
        } else {
            res.json({
                success: false,
                valid: false,
                error: 'Invalid or expired admin session'
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Additional authentication endpoints for compatibility
app.get('/api/auth/session', async (req, res) => {
    try {
        const loginResult = await performCodebeamerLogin('vectorCAST');
        
        if (loginResult.success) {
            res.json({
                success: true,
                csrfToken: loginResult.csrfToken,
                hasCookies: !!loginResult.cookies,
                codebeamerUrl: 'http://codebeamer.mdsit.co.kr:3008',
                user: 'vectorCAST',
                userRole: 'user'
            });
        } else {
            res.json({
                success: false,
                error: loginResult.error
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/api/auth/auto-login', (req, res) => {
    try {
        const autoLoginUrl = `${req.protocol}://${req.get('host')}/codebeamer-access`;
        res.json({
            success: true,
            autoLoginUrl: autoLoginUrl,
            codebeamerUrl: 'http://codebeamer.mdsit.co.kr:3008',
            user: 'vectorCAST',
            userRole: 'user',
            credentials: {
                username: 'vectorCAST',
                password: '1234'
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.post('/api/auth/validate', (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({
                success: false,
                error: 'Token is required'
            });
        }
        
        const isValid = isJWTValid(token);

        let userInfo = null;
        if (isValid) {
            try {
                const decoded = jwt.verify(token, CB_JWT_SECRET);
                userInfo = {
                    name: decoded.name,
                    role: 'admin'
                };
            } catch (e) {
                // Token verification failed
            }
        }
        
        res.json({
            success: true,
            valid: isValid,
            token: isValid ? token : null,
            user: userInfo
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// CodeBeamer access page for auto-login with item redirect
app.get('/codebeamer-access', async (req, res) => {
    try {
        const itemId = req.query.item || '2138'; // Default item or from query
        const loginResult = await performCodebeamerLogin('vectorCAST');
        
        if (loginResult.success) {
            const autoLoginPage = `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Codebeamer Auto Login - VectorCAST Report Hub</title>
                    <style>
                        body { 
                            font-family: Arial, sans-serif; 
                            margin: 0;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            height: 100vh;
                        }
                        .container {
                            text-align: center;
                            background: rgba(255,255,255,0.1);
                            padding: 40px;
                            border-radius: 20px;
                            backdrop-filter: blur(10px);
                            border: 1px solid rgba(255,255,255,0.2);
                            max-width: 500px;
                        }
                        .spinner { 
                            border: 4px solid rgba(255,255,255,0.3);
                            border-radius: 50%;
                            border-top: 4px solid white;
                            width: 50px;
                            height: 50px;
                            animation: spin 1s linear infinite;
                            margin: 20px auto;
                        }
                        @keyframes spin {
                            0% { transform: rotate(0deg); }
                            100% { transform: rotate(360deg); }
                        }
                        .countdown {
                            font-size: 18px;
                            margin: 20px 0;
                        }
                        .item-info {
                            background: rgba(255,255,255,0.1);
                            padding: 15px;
                            border-radius: 10px;
                            margin: 20px 0;
                            font-size: 14px;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="spinner"></div>
                        <h1><img src="/images/codebeamer_icon.png" alt="Codebeamer" style="width: 30px; height: 30px; vertical-align: middle; margin-right: 10px;"> 자동 로그인</h1>
                        <p>사용자 <strong>vectorCAST</strong>로 Codebeamer에 자동 로그인합니다...</p>
                        <div class="item-info">
                            📋 아이템 ID: <strong>${itemId}</strong><br>
                            🎯 로그인 후 해당 아이템으로 이동합니다
                        </div>
                        <p><span id="countdown">3</span>초 후 자동으로 제출됩니다</p>
                    </div>
                    
                    <form id="loginForm" method="POST" action="http://codebeamer.mdsit.co.kr:3008/login.spr" target="codebeamerWindow" style="display:none;">
                        <input type="hidden" name="_csrf" value="${loginResult.csrfToken}">
                        <input type="text" name="user" value="vectorCAST">
                        <input type="password" name="password" value="1234">
                    </form>
                    
                    <script>
                        let countdown = 3;
                        const countdownElement = document.getElementById('countdown');
                        
                        const timer = setInterval(() => {
                            countdown--;
                            countdownElement.textContent = countdown;
                            
                            if (countdown <= 0) {
                                clearInterval(timer);
                                
                                // Open CodeBeamer in new window and submit login
                                const codebeamerWindow = window.open('about:blank', 'codebeamerWindow');
                                document.getElementById('loginForm').submit();
                                
                                // Wait for login, then redirect the window to the specific item
                                setTimeout(() => {
                                    console.log('Redirecting to item ${itemId}...');
                                    if (codebeamerWindow && !codebeamerWindow.closed) {
                                        codebeamerWindow.location.href = 'http://codebeamer.mdsit.co.kr:3008/item/${itemId}';
                                    } else {
                                        // Fallback: open item in new window
                                        window.open('http://codebeamer.mdsit.co.kr:3008/item/${itemId}', '_blank');
                                    }
                                    // Close this auto-login window
                                    window.close();
                                }, 4000);
                            }
                        }, 1000);
                    </script>
                </body>
                </html>
            `;
            
            res.send(autoLoginPage);
        } else {
            // Fallback: redirect to login page with item redirect
            res.redirect(`http://codebeamer.mdsit.co.kr:3008/login.spr?redirect=/item/${itemId}`);
        }
        
    } catch (error) {
        console.error('Auto login error:', error);
        res.redirect(`http://codebeamer.mdsit.co.kr:3008/login.spr?redirect=/item/${itemId}`);
    }
});

// Additional JWT and login status endpoints from working app
app.get('/api/login-status', async (req, res) => {
    try {
        const loginResult = await performCodebeamerLogin('vectorCAST');
        res.json({
            success: loginResult.success,
            hasCsrfToken: !!loginResult.csrfToken,
            error: loginResult.error
        });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

app.get('/jwt-status', (req, res) => {
    const testToken = generateCodebeamerJWT('vectorCAST');
    const status = {
        jwtValid: isJWTValid(testToken),
        tokenExpiry: new Date((Math.floor(Date.now() / 1000) + (CB_TOKEN_VALID_MINUTES * 60)) * 1000).toISOString(),
        validMinutes: CB_TOKEN_VALID_MINUTES,
        renewTimeframe: CB_TOKEN_RENEW_TIMEFRAME,
        user: 'vectorCAST'
    };
    res.json(status);
});

app.get('/admin-session-test', (req, res) => {
    const adminToken = req.query.token || req.headers.authorization?.replace('Bearer ', '');
    
    if (!adminToken) {
        return res.json({
            success: false,
            error: 'No admin token provided',
            usage: 'Use ?token=YOUR_ADMIN_TOKEN or Authorization header',
            example: 'http://localhost:3001/admin-session-test?token=eyJ0eXAiOiJKV1QiLCJpZ25vcmVBcGlBY2Nlc3NQZXJtaXNzaW9uIjp0cnVlLCJpZ25vcmVUaHJvdHRsaW5nIjp0cnVlLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjb2RlQmVhbWVyIiwibmFtZSI6InNlamluLnBhcmsiLCJleHAiOjE3NzA3MjY1ODQsInR5cGUiOiJhY2Nlc3MiLCJpYXQiOjE3NTQ5NTg1ODR9.5k-QHKfHBgCa6L5dKlzE-WAQYukTEvDoxMZOlcuVWq0'
        });
    }
    
    const isValid = validateAdminSession(adminToken);
    
    if (isValid) {
        try {
            const decoded = jwt.verify(adminToken, CB_JWT_SECRET);
            res.json({
                success: true,
                adminValid: true,
                user: decoded.name,
                role: 'admin',
                exp: decoded.exp,
                expDate: new Date(decoded.exp * 1000).toISOString(),
                message: 'Admin session is valid. vectorCAST can now be logged in automatically.',
                nextStep: 'Use this admin token with /api/auth/jwt endpoint to get vectorCAST token'
            });
        } catch (error) {
            res.json({
                success: false,
                error: 'Token verification failed',
                details: error.message
            });
        }
    } else {
        res.json({
            success: false,
            adminValid: false,
            error: 'Invalid or expired admin session',
            message: 'Admin session (sejin.park) must be valid and active for vectorCAST auto-login'
        });
    }
});

app.post('/api/auth/webhook', (req, res) => {
    try {
        const { event, appId, userId, timestamp } = req.body;       
        console.log(`Auth webhook received: ${event} from app ${appId} for user ${userId} at ${timestamp}`);
        
        res.json({
            success: true,
            message: 'Webhook received',
            event: event,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Proxy middleware for CodeBeamer (alternative approach)
app.use('/codebeamer-proxy', createProxyMiddleware({
    target: 'http://codebeamer.mdsit.co.kr:3008',
    changeOrigin: true,
    pathRewrite: {
        '^/codebeamer-proxy': '' // Remove the proxy prefix
    },
    onProxyReq: (proxyReq, req, res) => {
        const adminToken = req.headers['x-admin-token'] || req.query.adminToken;
        
        if (!adminToken) {
            res.status(401).json({
                success: false,
                error: 'Admin token is required for proxy access'
            });
            return;
        }
        
        const isAdminValid = validateAdminSession(adminToken);
        
        if (!isAdminValid) {
            res.status(403).json({
                success: false,
                error: 'Invalid admin session for proxy access'
            });
            return;
        }
        
        const jwtToken = generateCodebeamerJWT('vectorCAST');
        proxyReq.setHeader('Authorization', `Bearer ${jwtToken}`);
        proxyReq.setHeader('X-Auth-Token', jwtToken);
        proxyReq.setHeader('X-User', 'vectorCAST');
        proxyReq.setHeader('X-Admin-Validated', 'true');
        
        console.log('Proxying request with JWT token for vectorCAST (admin validated):', jwtToken.substring(0, 20) + '...');
    },
    onProxyRes: (proxyRes, req, res) => {
        const jwtToken = generateCodebeamerJWT('vectorCAST');
        proxyRes.headers['X-JWT-Token'] = jwtToken;
        proxyRes.headers['X-Auth-Status'] = 'authenticated';
        proxyRes.headers['X-Admin-Validated'] = 'true';
        
        // Remove X-Frame-Options to allow embedding
        delete proxyRes.headers['x-frame-options'];
        // Add CORS headers
        proxyRes.headers['Access-Control-Allow-Origin'] = '*';
        proxyRes.headers['Access-Control-Allow-Credentials'] = 'true';
    }
}));