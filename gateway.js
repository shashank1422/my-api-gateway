const connectDB = require('./db');
connectDB(); 
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');


const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: 'Too many requests from this IP, please try again after 15 minutes.'
});


const authLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, 
    max: 5, 
    message: 'Too many login/signup attempts from this IP, please try again after 5 minutes.',
    standardHeaders: true, 
    legacyHeaders: false, 
});


const app = express();




app.use(express.static(path.join(__dirname, '..', 'dashboard-frontend', 'dist'))); 

const GATEWAY_PORT = process.env.PORT;
const MICROSERVICES_BASE_URL = process.env.MICROSERVICES_BASE_URL;
const JWT_SECRET = process.env.JWT_SECRET; 

const USER_SERVICE_URL = process.env.USER_SERVICE_URL;



app.use(cors()); 
app.use(cors({
    origin: 'https://my-dashboard-frontend-xcbi.onrender.com' 
}));
app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 


app.use(apiLimiter);


app.use((req, res, next) => {
    
    
    req.logEntry = {
        method: req.method,
        originalUrl: req.originalUrl,
        path: req.originalUrl.split('?')[0],
        ipAddress: req.ip,
        requestHeaders: req.headers,
        requestBody: req.body,
        query: req.query,
        params: req.params,
        requestStartTime: Date.now(),
        timestamp: new Date(),
        isAuthenticated: false, 
        isError: false,          
        errorMessage: ''         
    };

    
    if (
        req.originalUrl.startsWith('/public') ||
        req.originalUrl === '/' ||
        req.originalUrl.startsWith('/dashboard/metrics') ||
        
        req.originalUrl === '/signup' ||
        req.originalUrl === '/login'
        
    ) {
        return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        req.logEntry.isError = true;
        req.logEntry.statusCode = 401;
        req.logEntry.errorMessage = 'Authorization header missing or malformed';
        return res.status(401).json({ message: 'Authorization header missing or malformed (Bearer token expected)' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        req.logEntry.userId = decoded.id || decoded.userId || 'unknown_user';
        req.logEntry.isAuthenticated = true;
        console.log(`[Gateway Auth] User ${req.logEntry.userId} authenticated for ${req.originalUrl}`);
        next();
    } catch (err) {
        console.error('[Gateway Auth ERROR] JWT verification failed:', err);
        console.error('[Gateway Auth ERROR] Token that failed:', token); 
        req.logEntry.isError = true;
        req.logEntry.statusCode = 403;
        req.logEntry.errorMessage = `Invalid or expired token: ${err.message}`;
        return res.status(403).json({ message: 'Invalid or expired token' });
}
});


app.get('/dashboard/metrics/overall', async (req, res) => {
    try {
        const metrics = await RequestLog.aggregate([
            { $group: { _id: null, totalRequests: { $sum: 1 }, totalErrors: { $sum: { $cond: ['$isError', 1, 0] } }, averageResponseTime: { $avg: '$responseTimeMs' } } },
            { $project: { _id: 0, totalRequests: 1, totalErrors: 1, averageResponseTime: { $round: ['$averageResponseTime', 2] }, errorRate: { $cond: { if: { $eq: ['$totalRequests', 0] }, then: 0, else: { $multiply: [{ $divide: ['$totalErrors', '$totalRequests'] }, 100] } } } } }
        ]);
        const overallMetrics = metrics.length > 0 ? metrics[0] : { totalRequests: 0, totalErrors: 0, averageResponseTime: 0, errorRate: 0 };
        res.json(overallMetrics);
    } catch (error) {
        console.error('[Dashboard API Error] Failed to fetch overall metrics:', error);
        res.status(500).json({ message: 'Failed to fetch overall metrics', error: error.message });
    }
});

app.get('/dashboard/metrics/by-service', async (req, res) => {
    try {
        const metricsByService = await RequestLog.aggregate([
            { $group: { _id: '$targetService', totalRequests: { $sum: 1 }, totalErrors: { $sum: { $cond: ['$isError', 1, 0] } }, averageResponseTime: { $avg: '$responseTimeMs' } } },
            { $project: { _id: 0, serviceName: '$_id', totalRequests: 1, totalErrors: 1, averageResponseTime: { $round: ['$averageResponseTime', 2] }, errorRate: { $cond: { if: { $eq: ['$totalRequests', 0] }, then: 0, else: { $multiply: [{ $divide: ['$totalErrors', '$totalRequests'] }, 100] } } } } },
            { $sort: { serviceName: 1 } }
        ]);
        res.json(metricsByService);
    } catch (error) {
        console.error('[Dashboard API Error] Failed to fetch metrics by service:', error);
        res.status(500).json({ message: 'Failed to fetch metrics by service', error: error.message });
    }
});

app.get('/dashboard/metrics/requests-over-time', async (req, res) => {
    try {
        let matchCriteria = {};
        const period = req.query.period;
        if (period === '24h') {
            matchCriteria.timestamp = { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) };
        } else if (period === '7d') {
            matchCriteria.timestamp = { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) };
        }
        const requestsOverTime = await RequestLog.aggregate([
            Object.keys(matchCriteria).length > 0 ? { $match: matchCriteria } : { $match: {} },
            { $group: { _id: { year: { $year: '$timestamp' }, month: { $month: '$timestamp' }, day: { $dayOfMonth: '$timestamp' }, hour: { $hour: '$timestamp' } }, totalRequests: { $sum: 1 }, totalErrors: { $sum: { $cond: ['$isError', 1, 0] } }, averageResponseTime: { $avg: '$responseTimeMs' } } },
            { $project: { _id: 0, time: { $dateFromParts: { year: '$_id.year', month: '$_id.month', day: '$_id.day', hour: '$_id.hour', timezone: '+00:00' } }, totalRequests: 1, totalErrors: 1, averageResponseTime: { $round: ['$averageResponseTime', 2] } } },
            { $sort: { time: 1 } }
        ]);
        res.json(requestsOverTime);
    } catch (error) {
        console.error('[Dashboard API Error] Failed to fetch requests over time:', error);
        res.status(500).json({ message: 'Failed to fetch requests over time', error: error.message });
    }
});

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'Gateway is Healthy', timestamp: new Date() });
});

app.get('/verify-token', (req, res) => {
    
    req.logEntry = req.logEntry || {
        method: req.method,
        originalUrl: req.originalUrl,
        path: req.originalUrl.split('?')[0],
        ipAddress: req.ip,
        requestHeaders: req.headers,
        timestamp: new Date(),
        isAuthenticated: false,
        isError: false,
        errorMessage: ''
    };

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        req.logEntry.isError = true;
        req.logEntry.statusCode = 401;
        req.logEntry.errorMessage = 'Authorization header missing or malformed';
        return res.status(401).json({ valid: false, message: 'Authorization header missing or malformed' });
    }

    const token = authHeader.split(' ')[1];
    try {
        jwt.verify(token, JWT_SECRET);
        req.logEntry.isAuthenticated = true;
        req.logEntry.statusCode = 200;
        res.json({ valid: true });
    } catch (err) {
        req.logEntry.isError = true;
        req.logEntry.statusCode = 401;
        req.logEntry.errorMessage = `Invalid token: ${err.message}`;
        res.status(401).json({ valid: false, message: 'Invalid or expired token' });
    }
});



const RequestLog = require('./models/RequestLog'); 
app.use((req, res, next) => {
    
    req.logEntry = req.logEntry || { 
        method: req.method,
        originalUrl: req.originalUrl,
        path: req.originalUrl.split('?')[0],
        ipAddress: req.ip,
        requestHeaders: req.headers,
        requestBody: req.body,
        query: req.query,
        params: req.params,
        requestStartTime: Date.now(),
        timestamp: new Date(),
        isAuthenticated: false,
        isError: false,
        errorMessage: ''
    };
    console.log("came to loggig and metrics");
    
    const requestStartTime = req.logEntry.requestStartTime; 

    const originalSend = res.send;
    res.send = function (body) {
        console.log("came to hijacking or res.send wrapper");
        
        req.logEntry.statusCode = res.statusCode;
        req.logEntry.responseHeaders = res.getHeaders();
        req.logEntry.responseBodySize = Buffer.byteLength(JSON.stringify(body || {}), 'utf8');
        req.logEntry.responseTimeMs = Date.now() - requestStartTime;
   
        if (req.logEntry.path === '/signup' || req.logEntry.path === '/login') {
            if (req.logEntry.requestBody && req.logEntry.requestBody.password) {
                req.logEntry.requestBody.password = '[REDACTED]';
            }
            const logBody = typeof body === 'object' ? {...body} : body;
            if (logBody && typeof logBody === 'object' && logBody.token) {
                logBody.token = '[REDACTED]';
            }
        }

        if (req.originalUrl.startsWith('/users')) {
            req.logEntry.targetService = 'User Service';
        } else if (req.originalUrl.startsWith('/products')) {
            req.logEntry.targetService = 'Product Service';
        } else if (req.originalUrl.startsWith('/orders')) {
            req.logEntry.targetService = 'Order Service';
        
        } else if (req.originalUrl === '/signup' || req.originalUrl === '/login') {
            req.logEntry.targetService = 'Auth/User Service';
        
        } else if (req.originalUrl.startsWith('/error-service')) {
            req.logEntry.targetService = 'Error Service';
        } else if (req.originalUrl.startsWith('/dashboard')) { 
             req.logEntry.targetService = 'Gateway Dashboard API';
        }
         else {
            req.logEntry.targetService = 'Unknown Service';
        }
        
        if (req.logEntry.statusCode >= 400) {
            req.logEntry.isError = true;
        } else {
            req.logEntry.isError = false;
        }
        
        if (req.logEntry.isError && !req.logEntry.errorMessage) {
            if (typeof body === 'object' && body !== null && body.message) {
                req.logEntry.errorMessage = body.message;
            } else if (typeof body === 'string' && body.length > 0) {
                req.logEntry.errorMessage = body.substring(0, 200);
            } else {
                switch (req.logEntry.statusCode) {
                    case 400: req.logEntry.errorMessage = 'Bad Request'; break;
                    case 401: req.logEntry.errorMessage = 'Unauthorized'; break;
                    case 403: req.logEntry.errorMessage = 'Forbidden'; break;
                    case 404: req.logEntry.errorMessage = 'Not Found'; break;
                    case 500: req.logEntry.errorMessage = 'Internal Server Error'; break;
                    case 502: req.logEntry.errorMessage = 'Bad Gateway'; break;
                    case 503: req.logEntry.errorMessage = 'Service Unavailable'; break;
                    case 504: req.logEntry.errorMessage = 'Gateway Timeout'; break;
                    default: req.logEntry.errorMessage = `HTTP Error ${req.logEntry.statusCode}`;
                }
            }
        }
        const log = new RequestLog(req.logEntry);
        log.save()
            .then(() => console.log(`[Gateway Log] Saved log for ${req.originalUrl} - Status: ${req.logEntry.statusCode}`))
            .catch(err => console.error('[Gateway Log ERROR] Failed to save log:', err.message));

        originalSend.apply(res, arguments);
    };
    next();
});


app.use(['/signup', '/login'], authLimiter,async (req, res) => {
    console.log(`[Gateway Axios Catch-signup and login] Intercepted: ${req.method} ${req.originalUrl}`); 
    const targetUrl = `${USER_SERVICE_URL}${req.originalUrl}`; 

    console.log("catch signup and login endpoints");

    const axiosConfig = {
        method: req.method,
        url: targetUrl,
        validateStatus: (status) => true,
        headers: { ...req.headers },
    };

    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
        axiosConfig.data = req.body;
    }

    delete axiosConfig.headers['host'];
    delete axiosConfig.headers['connection'];
    delete axiosConfig.headers['content-length'];
    delete axiosConfig.headers['accept-encoding'];
    delete axiosConfig.headers['transfer-encoding'];

    try {
        const response = await axios(axiosConfig);

        for (const header in response.headers) {
            if (header.toLowerCase() !== 'transfer-encoding' && header.toLowerCase() !== 'content-encoding') {
                res.set(header, response.headers[header]);
            }
        }
        res.status(response.status);
        res.send(response.data);

    } catch (error) {
        console.error('[Gateway Proxy Error]:', error.message);

        req.logEntry.isError = true;
        req.logEntry.errorMessage = error.message;

        if (error.response) {
            console.error('[Gateway] Microservice responded with an invalid/unexpected error:', error.response.status, error.response.data);
            req.logEntry.statusCode = error.response.status;
            req.logEntry.responseHeaders = error.response.headers;
            req.logEntry.responseBodySize = Buffer.byteLength(JSON.stringify(error.response.data || {}), 'utf8');
            res.status(error.response.status).set(error.response.headers).send(error.response.data);
        } else if (error.request) {
            console.error('[Gateway] No response from microservice:', error.request);
            req.logEntry.statusCode = 503;
            req.logEntry.errorMessage = 'Service Unavailable: No response from microservice.';
            res.status(503).json({ message: 'Service Unavailable: No response from microservice.' });
        } else {
            console.error('[Gateway] Request setup error:', error.message);
            req.logEntry.statusCode = 500;
            req.logEntry.errorMessage = 'Internal Gateway Error: ' + error.message;
            res.status(500).json({ message: 'Internal Gateway Error.' });
        }
    }
})


app.use(async (req, res) => {
    console.log(`[Gateway Axios Catch-All] Intercepted: ${req.method} ${req.originalUrl}`); 
    const targetUrl = `${MICROSERVICES_BASE_URL}${req.originalUrl}`; 

    const axiosConfig = {
        method: req.method,
        url: targetUrl,
        validateStatus: (status) => true,
        headers: { ...req.headers },
    };

    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
        axiosConfig.data = req.body;
    }

    delete axiosConfig.headers['host'];
    delete axiosConfig.headers['connection'];
    delete axiosConfig.headers['content-length'];
    delete axiosConfig.headers['accept-encoding'];
    delete axiosConfig.headers['transfer-encoding'];

    try {
        const response = await axios(axiosConfig);

        for (const header in response.headers) {
            if (header.toLowerCase() !== 'transfer-encoding' && header.toLowerCase() !== 'content-encoding') {
                res.set(header, response.headers[header]);
            }
        }
        res.status(response.status);
        res.send(response.data);

    } catch (error) {
        console.error('[Gateway Proxy Error]:', error.message);

        req.logEntry.isError = true;
        req.logEntry.errorMessage = error.message;

        if (error.response) {
            console.error('[Gateway] Microservice responded with an invalid/unexpected error:', error.response.status, error.response.data);
            req.logEntry.statusCode = error.response.status;
            req.logEntry.responseHeaders = error.response.headers;
            req.logEntry.responseBodySize = Buffer.byteLength(JSON.stringify(error.response.data || {}), 'utf8');
            res.status(error.response.status).set(error.response.headers).send(error.response.data);
        } else if (error.request) {
            console.error('[Gateway] No response from microservice:', error.request);
            req.logEntry.statusCode = 503;
            req.logEntry.errorMessage = 'Service Unavailable: No response from microservice.';
            res.status(503).json({ message: 'Service Unavailable: No response from microservice.' });
        } else {
            console.error('[Gateway] Request setup error:', error.message);
            req.logEntry.statusCode = 500;
            req.logEntry.errorMessage = 'Internal Gateway Error: ' + error.message;
            res.status(500).json({ message: 'Internal Gateway Error.' });
        }
    }
});


app.use((err, req, res, next) => {
    console.error('[Gateway Global Error]', err.stack); 

    
    if (req.logEntry) {
        req.logEntry.isError = true;
        req.logEntry.statusCode = err.statusCode || 500;
        req.logEntry.errorMessage = err.message || 'Internal Server Error';
        
    }

    
    res.status(err.statusCode || 500).json({
        message: err.message || 'An unexpected error occurred.',
        error: process.env.NODE_ENV === 'production' ? {} : err.stack 
    });
});


app.listen(GATEWAY_PORT, () => {
    console.log(`API Gateway running on port ${GATEWAY_PORT}`);
});