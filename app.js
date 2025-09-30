require('dotenv').config({ path: __dirname + '/.env' });
const express = require('express');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const FormData = require('form-data');
const crypto = require('crypto');

const defaults = {
    cbApiUrl: process.env.CB_BASE_URL || '211.238.111.33:8080',
};

function normalizeCodebeamerUrl(baseUrl) {
    if (!baseUrl) return '';
    
    let url = baseUrl.trim();
    
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
    }
    
    if (!url.endsWith('/')) {
        url = url + '/';
    }
    
   if (!url.includes('/cb/') && !url.endsWith('/cb')) {
      url = url + 'cb/';
    }
    
    return url.replace(/\/+$/, '/');
}

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
const HOST = 'localhost';
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

// Middleware to log all requests

console.log('Starting application in normal mode');
loadSettingsFromLocalStorage();
startApp();

function startApp() {
    try {
        const server = app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        }).on('error', (err) => {
            console.error('Server error:', err.message);
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






app.get('/test', (req, res) => {
    res.json({ message: 'Server is working', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) { 
        return res.render('login', { 
            error: 'Username and password are required'
        }); 
    }
    res.redirect(`/main?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`);
});

app.get('/main', (req, res) => {
    const { username, password } = req.query;
    if (!username || !password) {
        return res.redirect('/');
    }
    res.render('list', {
        currentPath: '/',
        vectorcastPath: reportPaths.vectorcast || '',
        serverUrl: normalizeCodebeamerUrl(defaults.cbApiUrl),
        cbBaseUrl: defaults.cbApiUrl
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
        if (fs.existsSync(path.join(__dirname, 'settings.json'))) {
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

app.get('/report-settings', (req, res) => {
    res.render('report-settings', {
        currentPath: '/report-settings',
        vectorcastPath: reportPaths.vectorcast || '',
        serverUrl: defaults.cbApiUrl,
        trackerUrl: process.env.CB_BASE_URL || ''
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

        const normalizedUrl = normalizeCodebeamerUrl(defaults.cbApiUrl);
        const attachmentUrl = `${normalizedUrl}api/v3/items/${itemId}/attachments`;
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

app.post('/api/codebeamer/upload-report', async (req, res) => {
    try {
        const { fileName, fileContent, itemIds, username, password } = req.body;
        
        if (!fileName || !fileContent || !itemIds || !Array.isArray(itemIds) || itemIds.length === 0) {
            return res.status(400).json({ error: 'Missing required fields: fileName, fileContent, and itemIds array' });
        }
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const results = [];
        
        for (let i = 0; i < itemIds.length; i++) {
            const itemId = itemIds[i];
            
            console.log(`Processing upload ${i + 1}/${itemIds.length} for item ${itemId}`);
            
            try {
                const fileBuffer = Buffer.from(fileContent, 'base64');
                
                const auth = Buffer.from(`${username}:${password}`).toString('base64');
                const attachmentResult = await uploadAttachmentToCodeBeamer(
                    itemId, 
                    fileName, 
                    fileBuffer, 
                    auth
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

app.get('/api/codebeamer/projects', async (req, res) => {
    console.log('=== API PROJECTS ENDPOINT CALLED ===');
    try {
        const { username, password } = req.query;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        const normalizedUrl = normalizeCodebeamerUrl(defaults.cbApiUrl);
        const codebeamerUrl = `${normalizedUrl}api/v3/projects`;
        
        console.log('CB_BASE_URL:', process.env.CB_BASE_URL);
        console.log('Normalized URL:', normalizedUrl);
        console.log('Final CodeBeamer URL:', codebeamerUrl);
        
        const auth = Buffer.from(`${username}:${password}`).toString('base64');
        const response = await axios.get(codebeamerUrl, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json',
                'accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout: 10000,
            validateStatus: function (status) {
                return status < 500; 
            }
        });
        
        if (response.status === 401) {
            return res.status(401).json({ 
                error: 'Authentication failed with CodeBeamer instance',
                details: 'Please check your username and password'
            });
        }
        
        res.json(response.data);
    } catch (error) {
        console.error('Error fetching projects:', error.message);
        console.error('Error stack:', error.stack);
        if (error.response) {
            console.error('Error response status:', error.response.status);
            console.error('Error response data:', error.response.data);
        }
        res.status(500).json({ error: 'Failed to fetch projects: ' + error.message });
    }
});

app.get('/api/codebeamer/projects/:projectId/trackers', async (req, res) => {
    try {
        const { projectId } = req.params;
        const { username, password } = req.query;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        const normalizedUrl = normalizeCodebeamerUrl(defaults.cbApiUrl);
        const codebeamerUrl = `${normalizedUrl}api/v3/projects/${projectId}/trackers`;
        
        const auth = Buffer.from(`${username}:${password}`).toString('base64');
        const response = await axios.get(codebeamerUrl, {
            headers: {
                'Authorization': `Basic ${auth}`,
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

app.get('/api/codebeamer/trackers/:trackerId/items', async (req, res) => {
    try {
        const { trackerId } = req.params;
        const { maxItems, username, password } = req.query;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        const pageSize = 25;
        let allItems = [];
        let currentPage = 1;
        let hasMorePages = true;

        while (hasMorePages) {
            const normalizedUrl = normalizeCodebeamerUrl(defaults.cbApiUrl);
            const codebeamerUrl = `${normalizedUrl}api/v3/trackers/${trackerId}/items?page=${currentPage}&pageSize=${pageSize}`;
            
            console.log(`Fetching page ${currentPage} from: ${codebeamerUrl}`);
            
            try {
                const auth = Buffer.from(`${username}:${password}`).toString('base64');
                const response = await axios.get(codebeamerUrl, {
                    headers: {
                        'Authorization': `Basic ${auth}`,
                        'Content-Type': 'application/json',
                        'accept': 'application/json'
                    }
                });

                const responseData = response.data;
                let pageItems = [];

                if (Array.isArray(responseData)) {
                    pageItems = responseData;
                } else if (responseData.itemRefs && Array.isArray(responseData.itemRefs)) {
                    pageItems = responseData.itemRefs;
                } else if (responseData.items && Array.isArray(responseData.items)) {
                    pageItems = responseData.items;
                } else if (responseData.data && Array.isArray(responseData.data)) {
                    pageItems = responseData.data;
                }

                allItems = allItems.concat(pageItems);
                
                hasMorePages = pageItems.length === pageSize;
                currentPage++;
                
                if (maxItems && allItems.length >= parseInt(maxItems)) {
                    console.log(`Reached maximum items limit (${maxItems}), stopping pagination`);
                    allItems = allItems.slice(0, parseInt(maxItems));
                    break;
                }
                
                if (currentPage > 100) {
                    console.warn('Reached maximum page limit (100), stopping pagination');
                    break;
                }

                if (hasMorePages) {
                    console.log(`Waiting 1 second before fetching next page...`);
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            } catch (error) {
                if (error.response && error.response.status === 429) {
                    console.log('Rate limit hit, waiting 5 seconds before retrying...');
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    continue;
                } else {
                    throw error;
                }
            }
        }

        console.log(`Fetched ${allItems.length} total items across ${currentPage - 1} pages`);
        res.json(allItems);
    } catch (error) {
        console.error('Error fetching items:', error.message);
        res.status(500).json({ error: 'Failed to fetch items' });
    }
});

// Catch-all route to redirect any other paths to login (MUST be last)
app.get('*', (req, res) => {
    res.redirect('/');
});

