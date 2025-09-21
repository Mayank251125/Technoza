const yauzl = require('yauzl');
const xml2js = require('xml2js');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

// Try to import APK parser, fallback if not available
let ApkReader = null;
try {
  ApkReader = require('node-apk-parser');
} catch (err) {
  console.warn('node-apk-parser not available, falling back to basic parsing');
}

class APKAnalyzer {
  constructor() {
    this.knownBankingApps = new Set([
      'com.bankofamerica.bmobilebank',
      'com.chase.mobile',
      'com.wellsfargo.mobile',
      'com.citibank.mobile',
      'com.usbank.mobile',
    ]);

    this.suspiciousStrings = [
      'banking', 'password', 'pin', 'account', 'balance', 'transfer',
      'login', 'authenticate', 'security', 'credential', 'token',
      'keylogger', 'screen_record', 'accessibility_service',
      'device_admin', 'phone_state', 'sms', 'contacts'
    ];

    this.bankingKeywords = [
      'bank', 'credit', 'debit', 'account', 'balance', 'transaction',
      'transfer', 'payment', 'wallet', 'finance', 'money', 'card'
    ];
  }

  async analyzeAPK(apkPath) {
    try {
      console.log('Starting APK analysis for:', apkPath);

      const stats = await fs.stat(apkPath);
      const basicInfo = await this.extractBasicInfo(apkPath, stats);
      const manifest = await this.parseAndroidManifest(apkPath);
      const certificates = await this.extractCertificates(apkPath);
      const fileHashes = await this.calculateFileHashes(apkPath);
      const dexAnalysis = await this.analyzeDexFiles(apkPath);

      return {
        ...basicInfo,
        manifest,
        certificates,
        fileHashes,
        dexAnalysis,
        extractedAt: new Date()
      };

    } catch (error) {
      console.error('APK analysis failed:', error);
      throw new Error(`APK analysis failed: ${error.message}`);
    }
  }

  async extractBasicInfo(apkPath, stats) {
    return new Promise((resolve, reject) => {
      console.info("Using yauzl for APK analysis");
      yauzl.open(apkPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          console.error("Yauzl error:", err);
          return reject(err);
        };

        const info = {
          fileSize: stats.size,
          fileCount: 0,
          hasNativeCode: false,
          hasResources: false,
          hasDexFiles: false,
          isDebuggable: false,
          allowBackup: true,
          directories: new Set(),
          extensions: new Set()
        };

        zipfile.readEntry();
        zipfile.on('entry', (entry) => {
          info.fileCount++;

          const fileName = entry.fileName.toLowerCase();
          const ext = path.extname(fileName);
          if (ext) info.extensions.add(ext);

          const dir = path.dirname(entry.fileName);
          if (dir !== '.') info.directories.add(dir);

          if (fileName.includes('lib/') && (fileName.endsWith('.so') || fileName.endsWith('.dll'))) {
            info.hasNativeCode = true;
          }

          if (fileName.endsWith('.dex')) {
            info.hasDexFiles = true;
          }

          if (fileName.includes('res/') || fileName.includes('assets/')) {
            info.hasResources = true;
          }

          zipfile.readEntry();
        });

        zipfile.on('end', () => {
          console.info("Extracted basic info successfully through yauzl");
          resolve(info);
        });

        zipfile.on('error', reject);
      });
    });
  }

  async parseAndroidManifest(apkPath) {
    if (!ApkReader) {
        throw new Error('Could not parse manifest - node-apk-parser is not available.');
    }

    try {
        console.info("Parsing manifest with node-apk-parser");
        const reader = await ApkReader.readFile(apkPath);
        const manifest = await reader.readManifestSync();
        console.info("Parsed manifest successfully");
        return {
          package: manifest.package || '',
          versionCode: manifest.versionCode || '',
          versionName: manifest.versionName || '',
          permissions: manifest.usesPermissions.map(p => p.name) || [],
          features: manifest.usesFeatures || [],
          activities: manifest.application.activities || [],
          launcherActivities: manifest.application.launcherActivities || [],
          services: manifest.application.services || [],
          receivers: manifest.application.receivers || [],
          metadatas: manifest.application.metaDatas || [],
          minSdkVersion: manifest.usesSdk.minSdkVersion || '',
          targetSdkVersion: manifest.usesSdk.targetSdkVersion || '',
          compileSdkVersion: manifest.compileSdkVersion || '',
          isDebuggable: manifest.application?.debuggable || false,
          allowBackup: manifest.application?.allowBackup !== false,
          networkSecurityConfig: manifest.application?.networkSecurityConfig || '',
          usesCleartextTraffic: manifest.application?.usesCleartextTraffic !== false
        };
    } catch (jsError) {
        console.error('The node-apk-parser failed:', jsError);
        throw new Error(`Failed to parse manifest with node-apk-parser: ${jsError.message}`);
    }
  }

  async extractCertificates(apkPath) {
    return new Promise((resolve, reject) => {
      console.log("Starting Certificates Extraction using Yauzl");
      yauzl.open(apkPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          console.error("Yauzl error:", err);
          return reject(err);
        }

        const certificates = [];

        zipfile.readEntry();
        zipfile.on('entry', (entry) => {
          if (entry.fileName.startsWith('META-INF/') && 
              (entry.fileName.endsWith('.RSA') || entry.fileName.endsWith('.DSA'))) {

            zipfile.openReadStream(entry, (err, readStream) => {
              if (err) {
                zipfile.readEntry();
                return;
              }

              const chunks = [];
              readStream.on('data', chunk => chunks.push(chunk));
              readStream.on('end', () => {
                const buffer = Buffer.concat(chunks);
                certificates.push({
                  file: entry.fileName,
                  size: buffer.length,
                  hash: crypto.createHash('sha256').update(buffer).digest('hex')
                });
                zipfile.readEntry();
              });
            });
          } else {
            zipfile.readEntry();
          }
        });

        zipfile.on('end', () => {
          console.log("Certificates Extraction completed", certificates);
          resolve(certificates);
        });
      });
    });
  }

  async calculateFileHashes(apkPath) {
    const buffer = await fs.readFile(apkPath);
    console.info("Calculating file hashes");
    return {
      md5: crypto.createHash('md5').update(buffer).digest('hex'),
      sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
      sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
      size: buffer.length
    };
  }

  async analyzeDexFiles(apkPath) {
    return []; // Stubbing this as it's complex and might not be essential for a basic scan
  }

  async analyzeBankingCharacteristics(apkPath, apkInfo) {
    const analysis = {
      imitatesBankingApp: false,
      hasPhishingIndicators: false,
      suspiciousPermissions: [],
      suspiciousNetworking: false,
      uiSimilarity: 0,
      confidence: 0
    };

    try {
      if (apkInfo.manifest && apkInfo.manifest.package) {
        const packageName = apkInfo.manifest.package.toLowerCase();
        const hasBankingKeywords = this.bankingKeywords.some(keyword => packageName.includes(keyword));
        if (hasBankingKeywords && !this.knownBankingApps.has(apkInfo.manifest.package)) {
          analysis.imitatesBankingApp = true;
        }
      }

      if (apkInfo.manifest && apkInfo.manifest.permissions) {
        const permissions = apkInfo.manifest.permissions;
        const suspiciousPerms = [
          'android.permission.SEND_SMS', 'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS',
          'android.permission.BIND_ACCESSIBILITY_SERVICE', 'android.permission.BIND_DEVICE_ADMIN'
        ];
        analysis.suspiciousPermissions = permissions.filter(perm => suspiciousPerms.includes(perm));
        if (analysis.suspiciousPermissions.length > 0) {
          analysis.hasPhishingIndicators = true;
        }
      }

      let confidence = 0;
      if (analysis.imitatesBankingApp) confidence += 40;
      if (analysis.hasPhishingIndicators) confidence += 30;
      if (analysis.suspiciousPermissions.length > 2) confidence += 20;

      analysis.confidence = Math.min(confidence, 100);

      return analysis;

    } catch (error) {
      console.error('Banking characteristics analysis failed:', error);
      return { ...analysis, error: error.message };
    }
  }
}

module.exports = APKAnalyzer;