const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

// Import custom modules
const APKAnalyzer = require('./services/apkAnalyzer');
const SecurityScanner = require('./services/securityScanner');
const ThreatIntelligence = require('./services/threatIntelligence');

const app = express();
const PORT = process.env.PORT || 3000;

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.File({ filename: path.join(__dirname, 'logs/error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(__dirname, 'logs/combined.log') }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'null'],
  methods: ['GET', 'POST'],
  maxAge: 86400
}));

// This line is crucial for serving your index.html file from the root directory
app.use(express.static(path.join(__dirname, '..')));

// File upload configuration
const UPLOAD_DIR = path.join(__dirname, 'uploads/');
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      await fs.mkdir(UPLOAD_DIR, { recursive: true });
      cb(null, UPLOAD_DIR);
    } catch (err) {
      cb(err);
    }
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${uuidv4()}.apk`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 220 * 1024 * 1024 }, // 220MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/vnd.android.package-archive' || file.originalname.endsWith('.apk')) {
      cb(null, true);
    } else {
      cb(new Error('Only APK files are allowed.'), false);
    }
  }
});

// Initialize services
let apkAnalyzer, securityScanner, threatIntel;

async function initializeServices() {
  try {
    apkAnalyzer = new APKAnalyzer();
    securityScanner = new SecurityScanner();
    threatIntel = new ThreatIntelligence();
    await threatIntel.initialize();
    logger.info('All services initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize services:', error);
    process.exit(1);
  }
}

// Main APK scanning endpoint
app.post('/api/scan-apk', upload.single('apk'), async (req, res) => {
  const scanId = uuidv4();
  let filePath = null;

  try {
    if (!req.file) {
      logger.warn(`Scan attempt failed for scan ID ${scanId}: No file provided.`);
      return res.status(400).json({ success: false, message: 'No APK file provided.' });
    }

    filePath = req.file.path;
    const filename = req.file.originalname;
    logger.info(`Starting scan [ID: ${scanId}] for: ${filename}`);

    // --- Start Full Analysis ---
    // Each step is wrapped to ensure errors are caught and handled
    const apkInfo = await apkAnalyzer.analyzeAPK(filePath);
    logger.info(`[ID: ${scanId}] Basic analysis complete.`);
    
    const securityResults = await securityScanner.scanAPK(filePath, apkInfo);
    logger.info(`[ID: ${scanId}] Security scan complete.`);

    const bankingAnalysis = await apkAnalyzer.analyzeBankingCharacteristics(filePath, apkInfo);
    logger.info(`[ID: ${scanId}] Banking characteristics analysis complete.`);
    
    const threatResults = await threatIntel.checkAPK(apkInfo);
    logger.info(`[ID: ${scanId}] Threat intelligence check complete.`);
    
    // Combine analysis results here to generate a final risk assessment
    // This is a simplified example; your real logic might be more complex
    const isFake = securityResults.riskScore > 50 || bankingAnalysis.confidence > 60 || threatResults.isKnownThreat;
    const finalResult = {
        isFake: isFake,
        confidence: Math.max(securityResults.riskScore, bankingAnalysis.confidence),
        summary: `Scan complete for ${filename}. ${isFake ? 'Potential threats were found.' : 'No major threats detected.'}`,
        threats: threatResults.threatDetails || [],
        recommendations: isFake ? ['High risk detected. It is strongly recommended NOT to install this application.'] : ['No critical threats found, but always exercise caution.'],
    };
    
    logger.info(`Scan successful [ID: ${scanId}] for: ${filename}`);
    res.status(200).json({ success: true, result: finalResult });

  } catch (error) {
    logger.error(`Scan failed [ID: ${scanId}]:`, error);
    res.status(500).json({
      success: false,
      message: error.message || 'An unexpected error occurred during the scan. The file may be corrupt or unsupported.'
    });
  } finally {
    // This block ALWAYS runs, ensuring the uploaded file is deleted
    if (filePath) {
      try {
        await fs.unlink(filePath);
        logger.info(`Cleaned up file [ID: ${scanId}]: ${filePath}`);
      } catch (cleanupError) {
        logger.error(`Failed to cleanup file [ID: ${scanId}]:`, cleanupError);
      }
    }
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date() });
});

// Start the server
async function startServer() {
  await initializeServices();
  app.listen(PORT, () => {
    logger.info(`APK Security Scanner running on port ${PORT}`);
  });
}

startServer();

module.exports = app;