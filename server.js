const express = require('express');
const crypto = require('crypto');
const { URL } = require('url');
const { Session, initTLS } = require('node-tls-client');
const { generateBG } = require('./botguard');

const app = express();
app.use(express.json());

const MAX_RETRIES = 2;

const DEFAULT_PROFILE = {
  label: 'Chrome-Windows',
  tlsIdentifier: 'chrome_131',
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  secChUa: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
  secChUaMobile: '?0',
  secChUaPlatform: '"Windows"',
  platformType: 'desktop',
  acceptLanguages: 'en-US,en;q=0.9',
};

function getProfile(customUa) {
  if (!customUa) return { ...DEFAULT_PROFILE };
  const profile = { ...DEFAULT_PROFILE, userAgent: customUa };
  if (/Mobile|Android/i.test(customUa)) {
    profile.platformType = 'mobile';
    profile.secChUaMobile = '?1';
    profile.secChUaPlatform = '"Android"';
  }
  return profile;
}

function generateChr(profile) {
  const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
  if (profile.platformType === 'mobile') {
    return `[${rand(0,15)},${rand(0,10)},${rand(50,200)}]`;
  }
  return `[${rand(50,180)},${rand(20,100)},${rand(0,3)}]`;
}

function generateVh(siteUrl, siteKey, userAgent) {
  const hourBucket = String(Math.floor(Date.now() / 3600000));
  const salt = crypto.randomBytes(8).toString('hex');
  const raw = `${siteUrl}${siteKey}${userAgent}${hourBucket}${salt}`;
  const digest = crypto.createHash('md5').update(raw).digest('hex');
  const num = BigInt('0x' + digest.substring(0, 12)) % 10000000000n;
  return String(num).padStart(10, '0');
}

function humanDelay(ms = 300) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function generateCallback() {
  return crypto.randomBytes(12).toString('base64url').substring(0, 13);
}

function coString(siteUrl) {
  const parsed = new URL(siteUrl);
  const urlPort = `${parsed.protocol}//${parsed.hostname}:443`;
  return Buffer.from(urlPort).toString('base64url').replace(/=/g, '.');
}

async function solveRecaptcha(siteUrl, siteKey, action = 'submit', userAgent = null) {
  const profile = getProfile(userAgent);
  const session = new Session({
    clientIdentifier: profile.tlsIdentifier,
    randomTlsExtensionOrder: true,
  });

  // Get recaptcha version
  const siteHeaders = {
    'accept': 'text/html,application/xhtml+xml',
    'accept-language': profile.acceptLanguages,
    'user-agent': profile.userAgent,
  };
  
  let resp = await session.get(siteUrl, { headers: siteHeaders });
  let html = resp.body;
  
  let renderUrl = 'https://www.google.com/recaptcha/api2';
  const match = html.match(/['"](https:\/\/[^/]+\/recaptcha\/[^'"]+)['"]/);
  if (match) renderUrl = match[1];
  
  await humanDelay(200);
  
  // Get anchor token
  const params = new URLSearchParams({
    ar: '1',
    k: siteKey,
    co: coString(siteUrl),
    hl: 'en',
    v: '2.0',
    size: 'invisible',
    cb: generateCallback(),
  });
  
  const anchorUrl = `${renderUrl.split('.js')[0]}/anchor?${params}`;
  const anchorHeaders = {
    'accept': 'text/html',
    'accept-language': profile.acceptLanguages,
    'user-agent': profile.userAgent,
    'referer': siteUrl,
  };
  
  resp = await session.get(anchorUrl, { headers: anchorHeaders });
  html = resp.body;
  
  const tokenMatch = html.match(/recaptcha-token" value="([^"]+)"/);
  if (!tokenMatch) throw new Error('Token not found');
  const recaptchaToken = tokenMatch[1];
  
  await humanDelay(300);
  
  // Generate BotGuard
  let bg = '';
  const bgMatch = html.match(/recaptcha\.anchor\.Main\.init\("(.+?)"\)/s);
  if (bgMatch) {
    try {
      const raw = bgMatch[1];
      const decoded = new Function('return "' + raw + '"')();
      const data = JSON.parse(decoded);
      for (const item of data) {
        if (Array.isArray(item) && item[0] === 'bgdata') {
          bg = generateBG(item[4]);
          break;
        }
      }
    } catch(e) {}
  }
  
  // Get final token
  const chrValue = generateChr(profile);
  const vhValue = generateVh(siteUrl, siteKey, profile.userAgent);
  
  const reloadParams = new URLSearchParams({
    v: '2.0',
    reason: 'q',
    c: recaptchaToken,
    k: siteKey,
    co: coString(siteUrl),
    hl: 'en',
    size: 'invisible',
    chr: chrValue,
    vh: vhValue,
    bg: bg,
    sa: action,
  });
  
  const reloadHeaders = {
    'accept': '*/*',
    'accept-language': profile.acceptLanguages,
    'content-type': 'application/x-www-form-urlencoded',
    'user-agent': profile.userAgent,
    'origin': 'https://www.google.com',
    'referer': anchorUrl,
  };
  
  const reloadUrl = `${renderUrl.split('.js')[0]}/reload?k=${siteKey}`;
  resp = await session.post(reloadUrl, {
    headers: reloadHeaders,
    body: reloadParams.toString(),
  });
  
  const rrespMatch = resp.body.match(/"rresp","([^"]+)"/);
  if (!rrespMatch) throw new Error('Final token not found');
  
  return {
    token: rrespMatch[1],
    userAgent: profile.userAgent,
    bgGenerated: bg !== '',
  };
}

app.post('/solve', async (req, res) => {
  try {
    const { websiteURL, websiteKey, action, userAgent } = req.body;
    
    if (!websiteURL || !websiteKey) {
      return res.status(400).json({ success: false, error: 'websiteURL and websiteKey required' });
    }
    
    const result = await solveRecaptcha(websiteURL, websiteKey, action, userAgent);
    
    res.json({
      success: true,
      token: result.token,
      userAgent: result.userAgent,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 8080;

async function main() {
  await initTLS();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`reCAPTCHA solver running on port ${PORT}`);
  });
}

main().catch(console.error);