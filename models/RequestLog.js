const mongoose = require('mongoose');

const requestLogSchema = mongoose.Schema({
    
    method: { type: String, required: true },
    originalUrl: { type: String, required: true },
    path: { type: String, required: true }, 
    ipAddress: { type: String },
    requestHeaders: { type: Object },
    requestBody: { type: Object }, 
    query: { type: Object }, 
    params: { type: Object }, 
    timestamp: { type: Date, default: Date.now },
    requestStartTime: { type: Number }, 

    
    statusCode: { type: Number },
    responseHeaders: { type: Object },
    responseBodySize: { type: Number }, 
    responseTimeMs: { type: Number }, 

    
    targetService: { type: String }, 
    serviceUrl: { type: String }, 

    
    isError: { type: Boolean, default: false },
    errorMessage: { type: String },
    errorStack: { type: String },

    
    userId: { type: String },
    isAuthenticated: { type: Boolean, default: false }
},{
    timestamps: true 
});

const RequestLog = mongoose.model('RequestLog',requestLogSchema);
module.exports = RequestLog;
