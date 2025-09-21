// ./services/threatIntelligence.js
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });

class ThreatIntelligence {
  constructor() {
    this.virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;
    this.malwareBazaarApiKey = process.env.MALWAREBAZAAR_API_KEY;
    this.abuseIPDBApiKey = process.env.ABUSEIPDB_API_KEY;

    // Cache for threat intelligence results
    this.threatCache = new Map();
    this.cacheTimeout = 24 * 60 * 60 * 1000; // 24 hours

    // Known malicious hashes database
    this.knownMalwareHashes = new Set();
    this.maliciousDomains = new Set();
    this.suspiciousPackages = new Set();

    // Banking trojans and their variants
    this.bankingTrojans = new Map([
      ['Anubis', ['com.anubis.', 'anubis.banking', 'banking.anubis']],
      ['Cerberus', ['com.cerberus.', 'cerberus.bank', 'banking.cerberus']],
      ['Eventbot', ['com.eventbot.', 'eventbot.banking']],
      ['Ginp', ['com.ginp.', 'ginp.banking']],
      ['Gustuff', ['com.gustuff.', 'gustuff.banking']],
      ['Hydra', ['com.hydra.', 'hydra.banking']],
      ['Marcher', ['com.marcher.', 'marcher.banking']],
      ['Red Alert', ['com.redalert.', 'redalert.banking']],
      ['TeaBot', ['com.teabot.', 'teabot.banking']],
      ['Xenomorph', ['com.xenomorph.', 'xenomorph.banking']]
    ]);

    this.phishingDomains = new Set([
      'bit.ly',
      'tinyurl.com',
      'short.link',
      't.co'
    ]);
  }

  async initialize() {
    try {
      console.log('Initializing Threat Intelligence service...');

      // Load threat intelligence databases
      await this.loadMalwareHashes();
      await this.loadMaliciousDomains();
      await this.loadSuspiciousPackages();

      // Initialize API connections
      if (this.virusTotalApiKey) {
        console.log('VirusTotal API enabled');
      }

      if (this.malwareBazaarApiKey) {
        console.log('MalwareBazaar API enabled');
      }

      console.log('Threat Intelligence service initialized successfully');

    } catch (error) {
      console.error('Failed to initialize Threat Intelligence service:', error);
      throw error;
    }
  }

  async loadMalwareHashes() {
    try {
      const hashesFile = path.join(__dirname, '../data/malware_hashes.txt');

      try {
        const content = await fs.readFile(hashesFile, 'utf8');
        const hashes = content.split('\n').filter(line => line.trim());
        hashes.forEach(hash => this.knownMalwareHashes.add(hash.toLowerCase()));
        console.log(`Loaded ${hashes.length} known malware hashes`);
      } catch (fileError) {
        console.log('No local malware hashes file found, using defaults');
        this.loadDefaultMalwareHashes();
      }

    } catch (error) {
      console.error('Failed to load malware hashes:', error);
      this.loadDefaultMalwareHashes();
    }
  }

  loadDefaultMalwareHashes() {
    const defaultHashes = [
      'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
      'b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456a1',
      'c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456a1b2'
    ];

    defaultHashes.forEach(hash => this.knownMalwareHashes.add(hash));
  }

  async loadMaliciousDomains() {
    try {
      const domainsFile = path.join(__dirname, '../data/malicious_domains.txt');

      try {
        const content = await fs.readFile(domainsFile, 'utf8');
        const domains = content.split('\n').filter(line => line.trim());
        domains.forEach(domain => this.maliciousDomains.add(domain.toLowerCase()));
        console.log(`Loaded ${domains.length} malicious domains`);
      } catch (fileError) {
        console.log('No local malicious domains file found, using defaults');
        this.loadDefaultMaliciousDomains();
      }

    } catch (error) {
      console.error('Failed to load malicious domains:', error);
      this.loadDefaultMaliciousDomains();
    }
  }

  loadDefaultMaliciousDomains() {
    const defaultDomains = [
      'malicious-banking-site.com',
      'fake-bank-login.net',
      'phishing-bank.org',
      'steal-credentials.info',
      'banking-trojan-c2.xyz'
    ];

    defaultDomains.forEach(domain => this.maliciousDomains.add(domain));
  }

  async loadSuspiciousPackages() {
    try {
      const packagesFile = path.join(__dirname, '../data/suspicious_packages.txt');

      try {
        const content = await fs.readFile(packagesFile, 'utf8');
        const packages = content.split('\n').filter(line => line.trim());
        packages.forEach(pkg => this.suspiciousPackages.add(pkg.toLowerCase()));
        console.log(`Loaded ${packages.length} suspicious packages`);
      } catch (fileError) {
        console.log('No local suspicious packages file found, using defaults');
      }

    } catch (error) {
      console.error('Failed to load suspicious packages:', error);
    }
  }

  async checkAPK(apkInfo) {
    try {
      const results = {
        knownMalware: false,
        suspiciousDomains: 0,
        blacklistedHashes: [],
        reputationScore: 100,
        threatDetails: [],
        bankingTrojanMatch: null,
        virusTotalResults: null,
        malwareBazaarResults: null
      };

      // Check file hashes against known malware
      if (apkInfo.fileHashes) {
        const hashes = [
          apkInfo.fileHashes.md5,
          apkInfo.fileHashes.sha1,
          apkInfo.fileHashes.sha256
        ];

        for (const hash of hashes) {
          if (hash && this.knownMalwareHashes.has(hash.toLowerCase())) {
            results.knownMalware = true;
            results.blacklistedHashes.push(hash);
            results.reputationScore -= 50;
            results.threatDetails.push(`Known malware hash detected: ${hash}`);
            break;
          }
        }
      }

      // Check for banking trojan characteristics
      if (apkInfo.manifest && apkInfo.manifest.package) {
        const trojanMatch = this.checkBankingTrojanSignatures(apkInfo.manifest.package);
        if (trojanMatch) {
          results.bankingTrojanMatch = trojanMatch;
          results.reputationScore -= 40;
          results.threatDetails.push(`Banking trojan signature detected: ${trojanMatch}`);
        }
      }

      // Check suspicious package names
      if (apkInfo.manifest && apkInfo.manifest.package) {
        if (this.suspiciousPackages.has(apkInfo.manifest.package.toLowerCase())) {
          results.reputationScore -= 30;
          results.threatDetails.push('Package name matches known suspicious pattern');
        }
      }

      // Check domains in DEX files
      if (apkInfo.dexAnalysis) {
        results.suspiciousDomains = this.checkSuspiciousDomains(apkInfo.dexAnalysis);
        if (results.suspiciousDomains > 0) {
          results.reputationScore -= Math.min(results.suspiciousDomains * 10, 30);
        }
      }

      // Query external threat intelligence services
      if (apkInfo.fileHashes) {
        // VirusTotal check
        if (this.virusTotalApiKey) {
          results.virusTotalResults = await this.queryVirusTotal(apkInfo.fileHashes.sha256);
          if (results.virusTotalResults && results.virusTotalResults.malicious > 0) {
            results.reputationScore -= results.virusTotalResults.malicious * 5;
            results.threatDetails.push(`VirusTotal detections: ${results.virusTotalResults.malicious}`);
          }
        }

        // MalwareBazaar check
        if (this.malwareBazaarApiKey) {
          results.malwareBazaarResults = await this.queryMalwareBazaar(apkInfo.fileHashes.sha256);
          
          // If the main API failed due to authentication, try fallback
          if (results.malwareBazaarResults && results.malwareBazaarResults.error && 
              results.malwareBazaarResults.error.includes('authentication')) {
            console.log('Main MalwareBazaar API failed, trying fallback method...');
            results.malwareBazaarResults = await this.queryMalwareBazaarFallback(apkInfo.fileHashes.sha256);
          }
          
          if (results.malwareBazaarResults && results.malwareBazaarResults.found) {
            results.reputationScore -= 40;
            results.threatDetails.push('Sample found in MalwareBazaar database');
            
            if (results.malwareBazaarResults.family) {
              results.threatDetails.push(`Malware family: ${results.malwareBazaarResults.family}`);
            }
          }
        } else {
          // No API key configured, try the fallback method
          console.log('No MalwareBazaar API key configured, using fallback method...');
          results.malwareBazaarResults = await this.queryMalwareBazaarFallback(apkInfo.fileHashes.sha256);
          
          if (results.malwareBazaarResults && results.malwareBazaarResults.found) {
            results.reputationScore -= 30; // Slightly lower penalty for fallback method
            results.threatDetails.push('Sample found in MalwareBazaar database (public query)');
          }
        }
      }

      // Ensure reputation score doesn't go below 0
      results.reputationScore = Math.max(results.reputationScore, 0);

      return results;

    } catch (error) {
      console.error('Threat intelligence check failed:', error);
      return {
        knownMalware: false,
        suspiciousDomains: 0,
        blacklistedHashes: [],
        reputationScore: 50,
        threatDetails: [`Threat intelligence check failed: ${error.message}`],
        error: error.message
      };
    }
  }

  checkBankingTrojanSignatures(packageName) {
    const lowerPackage = packageName.toLowerCase();

    for (const [trojanName, signatures] of this.bankingTrojans) {
      for (const signature of signatures) {
        if (lowerPackage.includes(signature.toLowerCase())) {
          return trojanName;
        }
      }
    }

    return null;
  }

  checkSuspiciousDomains(dexAnalysis) {
    let suspiciousCount = 0;

    try {
      dexAnalysis.forEach(dex => {
        if (dex.stringAnalysis && dex.stringAnalysis.samples) {
          dex.stringAnalysis.samples.forEach(sample => {
            const text = (sample.text || '').toLowerCase();

            // Extract domains from URLs
            const urlRegex = /https?:\/\/([^\/\s]+)/gi;
            let match;

            while ((match = urlRegex.exec(text)) !== null) {
              const domain = match[1].toLowerCase();

              // Normalize domain (strip port/path)
              const host = domain.split(':')[0];

              // Check against known malicious domains
              if (this.maliciousDomains.has(host)) {
                suspiciousCount++;
                continue;
              }

              // Check against phishing domain patterns
              if (this.phishingDomains.has(host)) {
                suspiciousCount++;
                continue;
              }

              // Check for suspicious domain characteristics
              if (this.isDomainSuspicious(host)) {
                suspiciousCount++;
              }
            }
          });
        }
      });

    } catch (error) {
      console.error('Domain analysis failed:', error);
    }

    return suspiciousCount;
  }

  isDomainSuspicious(domain) {
    const suspiciousPatterns = [
      /bank.*login/i,
      /secure.*bank/i,
      /banking.*app/i,
      /mobile.*bank/i,
      /bank.*mobile/i,
      /financial.*secure/i,
      /account.*verify/i,
      /update.*bank/i,
      /\d+\.\d+\.\d+\.\d+/, // IP addresses
      /[a-z0-9]{10,}\.com/i, // Long random domain names
      /[a-z0-9]{5,}\.(tk|ml|ga|cf)$/i // Suspicious TLDs
    ];

    return suspiciousPatterns.some(pattern => pattern.test(domain));
  }

  async queryVirusTotal(sha256Hash) {
    try {
      if (!this.virusTotalApiKey) {
        return null;
      }

      const cacheKey = `vt_${sha256Hash}`;
      if (this.threatCache.has(cacheKey)) {
        const cached = this.threatCache.get(cacheKey);
        if (Date.now() - cached.timestamp < this.cacheTimeout) {
          return cached.data;
        }
      }

      const response = await axios.get(
        `https://www.virustotal.com/api/v3/files/${sha256Hash}`,
        {
          headers: {
            'x-apikey': this.virusTotalApiKey
          },
          timeout: 10000
        }
      );

      const data = response.data;
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      const result = {
        found: true,
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        engines: (stats.malicious || 0) + (stats.suspicious || 0),
        scanDate: data?.data?.attributes?.last_analysis_date || null,
        reputation: data?.data?.attributes?.reputation || 0
      };

      this.threatCache.set(cacheKey, { data: result, timestamp: Date.now() });

      return result;

    } catch (error) {
      if (error.response && error.response.status === 404) {
        return { found: false, error: 'File not found in VirusTotal' };
      }

      console.error('VirusTotal query failed:', error.message);
      return { found: false, error: error.message };
    }
  }

  async queryMalwareBazaar(sha256Hash) {
    try {
      if (!this.malwareBazaarApiKey) {
        console.log('MalwareBazaar API key not configured');
        return null;
      }

      const cacheKey = `mb_${sha256Hash}`;
      if (this.threatCache.has(cacheKey)) {
        const cached = this.threatCache.get(cacheKey);
        if (Date.now() - cached.timestamp < this.cacheTimeout) {
          return cached.data;
        }
      }

      // MalwareBazaar API requires specific format
      const formData = new URLSearchParams();
      formData.append('query', 'get_info');
      formData.append('hash', sha256Hash);

      console.log(`Querying MalwareBazaar for hash: ${sha256Hash}`);

      const response = await axios.post(
        'https://mb-api.abuse.ch/api/v1/',
        formData,
        {
          headers: {
            'Auth-Key': this.malwareBazaarApiKey,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'CyberShield-Security-Scanner'
          },
          timeout: 15000,
          validateStatus: function (status) {
            return status >= 200 && status < 500; // Don't reject on 4xx errors
          }
        }
      );

      // Handle API response
      if (response.status === 401) {
        console.error('MalwareBazaar API authentication failed - check your API key');
        return { found: false, error: 'Authentication failed - invalid API key' };
      }

      if (response.status === 403) {
        console.error('MalwareBazaar API access forbidden - check API key permissions');
        return { found: false, error: 'Access forbidden - check API key permissions' };
      }

      if (response.status === 429) {
        console.error('MalwareBazaar API rate limit exceeded');
        return { found: false, error: 'Rate limit exceeded - try again later' };
      }

      if (response.status !== 200) {
        console.error(`MalwareBazaar API returned status ${response.status}`);
        return { found: false, error: `API returned status ${response.status}` };
      }

      const data = response.data || {};
      console.log('MalwareBazaar response:', JSON.stringify(data, null, 2));

      // Check if the query was successful
      if (data.query_status === 'hash_not_found') {
        return {
          found: false,
          signature: null,
          family: null,
          tags: [],
          firstSeen: null,
          lastSeen: null
        };
      }

      if (data.query_status === 'illegal_hash') {
        console.error('MalwareBazaar reported illegal hash format');
        return { found: false, error: 'Invalid hash format' };
      }

      const found = data.query_status === 'ok' && Array.isArray(data.data) && data.data.length > 0;
      const entry = found ? data.data[0] : null;

      const result = {
        found,
        signature: entry?.signature || null,
        family: entry?.malware || null,
        tags: entry?.tags || [],
        firstSeen: entry?.first_seen || null,
        lastSeen: entry?.last_seen || null,
        deliveryMethod: entry?.delivery_method || null,
        intelligence: entry?.intelligence || {}
      };

      this.threatCache.set(cacheKey, { data: result, timestamp: Date.now() });

      return result;

    } catch (error) {
      console.error('MalwareBazaar query failed:');
      console.error('Error message:', error.message);
      console.error('Error response:', error.response?.data);
      console.error('Status code:', error.response?.status);
      
      if (error.response?.status === 401) {
        return { found: false, error: 'MalwareBazaar API authentication failed - check your API key' };
      } else if (error.response?.status === 403) {
        return { found: false, error: 'MalwareBazaar API access forbidden' };
      } else if (error.response?.status === 429) {
        return { found: false, error: 'MalwareBazaar API rate limit exceeded' };
      } else if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
        return { found: false, error: 'MalwareBazaar API unreachable - network error' };
      } else if (error.code === 'ETIMEDOUT') {
        return { found: false, error: 'MalwareBazaar API timeout' };
      }
      
      return { found: false, error: error.message };
    }
  }

  // Fallback method for when API is not available
  async queryMalwareBazaarFallback(sha256Hash) {
    console.log('Using MalwareBazaar fallback method (no API key required)');
    
    try {
      // Try the public query endpoint that doesn't require API key
      const response = await axios.post(
        'https://mb-api.abuse.ch/api/v1/',
        new URLSearchParams({
          'query': 'get_info',
          'hash': sha256Hash
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'CyberShield-Security-Scanner'
          },
          timeout: 10000
        }
      );

      const data = response.data || {};
      const found = data.query_status === 'ok' && Array.isArray(data.data) && data.data.length > 0;
      
      return {
        found,
        signature: found ? data.data[0]?.signature : null,
        family: found ? data.data[0]?.malware : null,
        tags: found ? data.data[0]?.tags || [] : [],
        source: 'MalwareBazaar (public)'
      };

    } catch (error) {
      console.error('MalwareBazaar fallback query failed:', error.message);
      return { found: false, error: error.message };
    }
  }
}

// Export the class
module.exports = ThreatIntelligence;
