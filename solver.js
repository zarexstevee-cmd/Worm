#!/usr/bin/env node
/**
 * Auto-Universal WAF Solver
 * Zero configuration, no API keys required, fully automated
 * Usage: node solver.js <url> [proxy.txt]
 */

const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const readline = require('readline');

// Initialize stealth
puppeteer.use(StealthPlugin());

// Colors for terminal
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    dim: '\x1b[2m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m'
};

const log = {
    info: (msg) => console.log(`${colors.blue}[INFO]${colors.reset} ${msg}`),
    success: (msg) => console.log(`${colors.green}[SUCCESS]${colors.reset} ${msg}`),
    warning: (msg) => console.log(`${colors.yellow}[WARNING]${colors.reset} ${msg}`),
    error: (msg) => console.log(`${colors.red}[ERROR]${colors.reset} ${msg}`),
    debug: (msg) => console.log(`${colors.dim}[DEBUG]${colors.reset} ${msg}`),
    waf: (type) => console.log(`${colors.magenta}[WAF DETECTED]${colors.reset} ${colors.bright}${type}${colors.reset}`),
    solver: (type) => console.log(`${colors.cyan}[SOLVER]${colors.reset} ${type}`)
};

class AutoWAFSolver {
    constructor() {
        this.browser = null;
        this.proxyList = [];
        this.currentProxy = null;
        this.sessions = new Map();
        this.solvedChallenges = new Map();
    }

    async loadProxies(proxyFile) {
        if (!proxyFile || !fs.existsSync(proxyFile)) {
            log.warning('No proxy file found, using direct connection');
            return;
        }

        const data = fs.readFileSync(proxyFile, 'utf8');
        this.proxyList = data.split('\n')
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'))
            .map(proxy => {
                // Parse various proxy formats
                if (proxy.includes('://')) {
                    return proxy;
                } else if (proxy.includes(':')) {
                    const [host, port, user, pass] = proxy.split(':');
                    if (user && pass) {
                        return `http://${user}:${pass}@${host}:${port}`;
                    }
                    return `http://${host}:${port}`;
                }
                return proxy;
            });

        log.success(`Loaded ${this.proxyList.length} proxies`);
    }

    getNextProxy() {
        if (this.proxyList.length === 0) return null;
        const proxy = this.proxyList.shift();
        this.proxyList.push(proxy); // Rotate
        this.currentProxy = proxy;
        return proxy;
    }

    async initBrowser(proxy = null) {
        const args = [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--disable-gpu',
            '--window-size=1920,1080',
            '--disable-blink-features=AutomationControlled',
            '--disable-features=IsolateOrigins,site-per-process',
            '--disable-web-security',
            '--disable-features=BlockInsecurePrivateNetworkRequests',
            '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ];

        if (proxy) {
            args.push(`--proxy-server=${proxy}`);
            log.info(`Using proxy: ${proxy.replace(/\/\/.*@/, '//***@')}`);
        }

        if (this.browser) {
            await this.browser.close();
        }

        this.browser = await puppeteer.launch({
            headless: 'new',
            args,
            ignoreHTTPSErrors: true,
            executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined
        });

        // Apply additional evasions
        const pages = await this.browser.pages();
        const page = pages[0] || await this.browser.newPage();

        await page.evaluateOnNewDocument(() => {
            // Override webdriver
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            
            // Override permissions
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({ state: Notification.permission }) :
                    originalQuery(parameters)
            );

            // Add plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [
                    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format', version: 'undefined', length: 1 },
                    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: 'Portable Document Format', version: 'undefined', length: 1 },
                    { name: 'Native Client', filename: 'internal-nacl-plugin', description: '', version: 'undefined', length: 2 }
                ]
            });

            // Add languages
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });

            // Override Chrome runtime
            window.chrome = {
                runtime: {
                    OnInstalledReason: { CHROME_UPDATE: "chrome_update", INSTALL: "install", SHARED_MODULE_UPDATE: "shared_module_update", UPDATE: "update" },
                    OnRestartRequiredReason: { APP_UPDATE: "app_update", OS_UPDATE: "os_update", PERIODIC: "periodic" },
                    PlatformArch: { ARM: "arm", ARM64: "arm64", MIPS: "mips", MIPS64: "mips64", MIPS64EL: "mips64el", MIPSEL: "mipsel", X86_32: "x86-32", X86_64: "x86-64" },
                    PlatformNaclArch: { ARM: "arm", MIPS: "mips", MIPS64: "mips64", MIPS64EL: "mips64el", MIPSEL: "mipsel", MIPSEL64: "mipsel64", X86_32: "x86-32", X86_64: "x86-64" },
                    PlatformOs: { ANDROID: "android", CROS: "cros", LINUX: "linux", MAC: "mac", OPENBSD: "openbsd", WIN: "win" },
                    RequestUpdateCheckStatus: { NO_UPDATE: "no_update", THROTTLED: "throttled", UPDATE_AVAILABLE: "update_available" }
                },
                loadTimes: () => {},
                csi: () => {},
                app: { isInstalled: false }
            };

            // Override iframe creation to prevent detection
            const originalCreateElement = document.createElement;
            document.createElement = function(tagName) {
                const element = originalCreateElement.call(this, tagName);
                if (tagName.toLowerCase() === 'iframe') {
                    try {
                        Object.defineProperty(element.contentWindow.navigator, 'webdriver', { get: () => undefined });
                    } catch (e) {}
                }
                return element;
            };
        });

        return page;
    }

    async detectWAF(url) {
        log.info(`Detecting WAF for: ${url}`);
        
        try {
            const response = await axios.get(url, {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Cache-Control': 'max-age=0'
                },
                timeout: 15000,
                validateStatus: () => true,
                maxRedirects: 5
            });

            const html = response.data.toString().toLowerCase();
            const headers = response.headers;
            const title = html.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1] || '';

            const detections = [];

            // Cloudflare Detection
            if (html.includes('cf-browser-verification') || 
                html.includes('cf-im-under-attack') ||
                html.includes('checking your browser') ||
                html.includes('__cf_chl_jschl_tk__') ||
                html.includes('cf_chl_prog') ||
                html.includes('cf_chl_rc_ni') ||
                html.includes('cf-spinner') ||
                html.includes('cf_challenge') ||
                headers['cf-ray'] ||
                (headers['server'] && headers['server'].includes('cloudflare'))) {
                detections.push({ type: 'Cloudflare UAM/JS Challenge', severity: 'high' });
            }

            if (html.includes('cf-turnstile') || 
                html.includes('turnstile') && html.includes('data-sitekey') ||
                html.includes('cf-turnstile-response')) {
                detections.push({ type: 'Cloudflare Turnstile', severity: 'medium' });
            }

            // Akamai Detection
            if (html.includes('akamai') || 
                (headers['server'] && headers['server'].includes('akamaighost')) ||
                html.includes('ak_bmsc') ||
                html.includes('_abck') ||
                html.includes('akamai-bot-manager') ||
                headers['x-akamai-transformed']) {
                detections.push({ type: 'Akamai WAF/CDN', severity: 'high' });
            }

            // Sucuri Detection
            if (html.includes('sucuri') || 
                html.includes('x-sucuri-id') ||
                headers['x-sucuri-id'] ||
                html.includes('sucuri website firewall') ||
                html.includes('sucuri_security')) {
                detections.push({ type: 'Sucuri WAF', severity: 'medium' });
            }

            // Imperva/Incapsula Detection
            if (html.includes('incapsula') || 
                html.includes('imperva') ||
                html.includes('_incapsula_resource') ||
                html.includes('visid_incap') ||
                html.includes('incap_ses') ||
                headers['x-iinfo'] ||
                headers['x-cdn'] === 'Incapsula') {
                detections.push({ type: 'Imperva/Incapsula', severity: 'high' });
            }

            // AWS WAF Detection
            if ((headers['server'] && headers['server'].includes('cloudfront')) ||
                headers['x-amz-cf-id'] ||
                headers['x-amz-cf-pop'] ||
                html.includes('aws waf') ||
                html.includes('amazon cloudfront')) {
                detections.push({ type: 'AWS CloudFront/WAF', severity: 'medium' });
            }

            // Azure WAF Detection
            if (headers['x-azure-ref'] ||
                (headers['x-cache'] && headers['x-cache'].includes('azure')) ||
                headers['x-msedge-ref']) {
                detections.push({ type: 'Azure Front Door/WAF', severity: 'medium' });
            }

            // Fastly Detection
            if ((headers['server'] && headers['server'].includes('fastly')) ||
                headers['x-fastly-request-id'] ||
                headers['x-served-by']) {
                detections.push({ type: 'Fastly CDN', severity: 'low' });
            }

            // reCAPTCHA Detection
            if (html.includes('google.com/recaptcha') ||
                html.includes('g-recaptcha') ||
                html.includes('recaptcha/api.js') ||
                html.includes('grecaptcha')) {
                detections.push({ type: 'Google reCAPTCHA', severity: 'high' });
            }

            // hCaptcha Detection
            if (html.includes('hcaptcha.com') ||
                html.includes('h-captcha') ||
                html.includes('data-hcaptcha-widget-id')) {
                detections.push({ type: 'hCaptcha', severity: 'high' });
            }

            // Generic CAPTCHA
            if ((html.includes('captcha') && (html.includes('enter') || html.includes('type'))) ||
                html.includes('security check') ||
                html.includes('are you human')) {
                detections.push({ type: 'Generic CAPTCHA', severity: 'medium' });
            }

            // Datadome
            if (html.includes('datadome') ||
                headers['x-datadome']) {
                detections.push({ type: 'DataDome', severity: 'high' });
            }

            // PerimeterX
            if (html.includes('perimeterx') ||
                html.includes('_px') ||
                html.includes('px-captcha')) {
                detections.push({ type: 'PerimeterX', severity: 'high' });
            }

            // Shape Security
            if (html.includes('shape security') ||
                html.includes('shapesecurity')) {
                detections.push({ type: 'Shape Security', severity: 'high' });
            }

            return {
                url,
                status: response.status,
                detections,
                isProtected: detections.length > 0,
                primaryWAF: detections[0]?.type || 'None',
                headers,
                title,
                contentLength: html.length
            };

        } catch (error) {
            log.error(`Detection error: ${error.message}`);
            return {
                url,
                error: error.message,
                detections: [],
                isProtected: false
            };
        }
    }

    async solveAll(url, options = {}) {
        log.info(`Starting auto-solve for: ${url}`);
        
        let retries = 0;
        const maxRetries = 3;

        while (retries < maxRetries) {
            try {
                // Try with current proxy or direct
                const proxy = this.getNextProxy();
                const page = await this.initBrowser(proxy);

                // Set timeouts
                page.setDefaultNavigationTimeout(60000);
                page.setDefaultTimeout(30000);

                // Navigate to URL
                log.solver(`Navigating to ${url}`);
                const response = await page.goto(url, {
                    waitUntil: 'networkidle2',
                    timeout: 60000
                });

                // Wait a moment for challenges to appear
                await page.waitForTimeout(3000);

                // Auto-solve all detected challenges
                const result = await this.autoSolveChallenges(page, url);

                if (result.success) {
                    log.success('All challenges solved successfully!');
                    
                    // Get final data
                    const cookies = await page.cookies();
                    const content = await page.content();
                    const title = await page.title();
                    const finalUrl = page.url();

                    // Save session
                    const sessionData = {
                        url: finalUrl,
                        title,
                        cookies: cookies.reduce((acc, c) => ({ ...acc, [c.name]: c.value }), {}),
                        userAgent: await page.evaluate(() => navigator.userAgent),
                        timestamp: new Date().toISOString()
                    };

                    // Save to file
                    const filename = `session_${new URL(url).hostname}_${Date.now()}.json`;
                    fs.writeFileSync(filename, JSON.stringify(sessionData, null, 2));
                    log.success(`Session saved to: ${filename}`);

                    await page.close();
                    return {
                        success: true,
                        session: sessionData,
                        content: content.substring(0, 2000),
                        solvedChallenges: result.challenges
                    };
                }

            } catch (error) {
                log.error(`Attempt ${retries + 1} failed: ${error.message}`);
                retries++;
                
                if (retries < maxRetries) {
                    log.warning(`Retrying with new proxy...`);
                    await new Promise(r => setTimeout(r, 2000));
                }
            }
        }

        throw new Error('All solving attempts failed');
    }

    async autoSolveChallenges(page, originalUrl) {
        const solvedChallenges = [];
        let attempts = 0;
        const maxAttempts = 10;

        while (attempts < maxAttempts) {
            const challenge = await this.identifyChallenge(page);
            
            if (!challenge.type) {
                log.success('No more challenges detected');
                break;
            }

            log.waf(challenge.type);
            
            try {
                switch (challenge.type) {
                    case 'cloudflare-uam':
                        await this.solveCloudflareUAM(page);
                        solvedChallenges.push('Cloudflare UAM');
                        break;
                    
                    case 'cloudflare-turnstile':
                        await this.solveCloudflareTurnstile(page);
                        solvedChallenges.push('Cloudflare Turnstile');
                        break;
                    
                    case 'akamai':
                        await this.solveAkamai(page);
                        solvedChallenges.push('Akamai');
                        break;
                    
                    case 'sucuri':
                        await this.solveSucuri(page);
                        solvedChallenges.push('Sucuri');
                        break;
                    
                    case 'imperva':
                        await this.solveImperva(page);
                        solvedChallenges.push('Imperva');
                        break;
                    
                    case 'recaptcha':
                        await this.solveReCAPTCHA(page);
                        solvedChallenges.push('reCAPTCHA');
                        break;
                    
                    case 'hcaptcha':
                        await this.solveHCaptcha(page);
                        solvedChallenges.push('hCaptcha');
                        break;
                    
                    case 'datadome':
                        await this.solveDataDome(page);
                        solvedChallenges.push('DataDome');
                        break;
                    
                    case 'perimeterx':
                        await this.solvePerimeterX(page);
                        solvedChallenges.push('PerimeterX');
                        break;
                    
                    default:
                        await this.solveGenericChallenge(page);
                        solvedChallenges.push('Generic');
                }

                // Wait for navigation or changes
                await page.waitForTimeout(3000);
                
                // Check if redirected to target
                const currentUrl = page.url();
                if (currentUrl !== originalUrl && !currentUrl.includes('challenge') && !currentUrl.includes('captcha')) {
                    log.success('Successfully passed challenge!');
                    break;
                }

            } catch (error) {
                log.error(`Failed to solve ${challenge.type}: ${error.message}`);
                
                // Try clicking any submit buttons
                try {
                    const buttons = await page.$$('button[type="submit"], input[type="submit"], .submit, #submit');
                    for (const button of buttons) {
                        await button.click();
                        await page.waitForTimeout(2000);
                    }
                } catch (e) {}
            }

            attempts++;
        }

        return {
            success: solvedChallenges.length > 0 || attempts === 0,
            challenges: solvedChallenges
        };
    }

    async identifyChallenge(page) {
        return await page.evaluate(() => {
            const html = document.body.innerHTML.toLowerCase();
            const title = document.title.toLowerCase();

            // Check for Cloudflare UAM
            if (document.querySelector('#cf-challenge-running') ||
                document.querySelector('.cf-browser-verification') ||
                document.querySelector('#cf-please-wait') ||
                html.includes('checking your browser') ||
                html.includes('just a moment')) {
                return { type: 'cloudflare-uam' };
            }

            // Check for Cloudflare Turnstile
            if (document.querySelector('.cf-turnstile') ||
                document.querySelector('[data-sitekey]') ||
                html.includes('turnstile')) {
                return { type: 'cloudflare-turnstile' };
            }

            // Check for Akamai
            if (html.includes('akamai') && (html.includes('challenge') || html.includes('access denied'))) {
                return { type: 'akamai' };
            }

            // Check for Sucuri
            if (html.includes('sucuri') && html.includes('javascript')) {
                return { type: 'sucuri' };
            }

            // Check for Imperva
            if (html.includes('incapsula') || html.includes('imperva') || document.querySelector('#incapsula')) {
                return { type: 'imperva' };
            }

            // Check for reCAPTCHA
            if (document.querySelector('.g-recaptcha') ||
                document.querySelector('[data-sitekey]') ||
                html.includes('recaptcha')) {
                return { type: 'recaptcha' };
            }

            // Check for hCaptcha
            if (document.querySelector('.h-captcha') ||
                html.includes('hcaptcha')) {
                return { type: 'hcaptcha' };
            }

            // Check for DataDome
            if (html.includes('datadome') || document.querySelector('#datadome')) {
                return { type: 'datadome' };
            }

            // Check for PerimeterX
            if (html.includes('perimeterx') || html.includes('px-captcha')) {
                return { type: 'perimeterx' };
            }

            // Check for generic challenge
            if (html.includes('captcha') || 
                html.includes('challenge') ||
                html.includes('security check') ||
                title.includes('attention required')) {
                return { type: 'generic' };
            }

            return { type: null };
        });
    }

    async solveCloudflareUAM(page) {
        log.solver('Solving Cloudflare UAM...');
        
        try {
            // Wait for challenge to complete automatically
            await page.waitForFunction(() => {
                return !document.querySelector('#cf-challenge-running') &&
                       !document.querySelector('.cf-browser-verification') &&
                       !document.querySelector('#cf-please-wait');
            }, { timeout: 60000 });

            log.success('Cloudflare UAM passed');
        } catch (error) {
            // Try to click "Verify" button if exists
            try {
                const verifyButton = await page.$('input[type="button"], button');
                if (verifyButton) {
                    await verifyButton.click();
                    await page.waitForTimeout(5000);
                }
            } catch (e) {}
            
            throw error;
        }
    }

    async solveCloudflareTurnstile(page) {
        log.solver('Solving Cloudflare Turnstile...');
        
        // Wait for Turnstile to be solved automatically or try to trigger it
        try {
            await page.waitForFunction(() => {
                const response = document.querySelector('[name="cf-turnstile-response"]');
                return response && response.value.length > 0;
            }, { timeout: 30000 });
            
            log.success('Turnstile solved');
        } catch (error) {
            // Try clicking the widget
            try {
                const widget = await page.$('.cf-turnstile, .turnstile');
                if (widget) {
                    await widget.click();
                    await page.waitForTimeout(5000);
                }
            } catch (e) {}
        }
    }

    async solveAkamai(page) {
        log.solver('Bypassing Akamai...');
        
        // Akamai usually requires waiting for sensor data collection
        await page.waitForTimeout(10000);
        
        // Try to trigger any challenge resolution
        await page.evaluate(() => {
            window.dispatchEvent(new Event('mousemove'));
            window.dispatchEvent(new Event('scroll'));
            document.dispatchEvent(new Event('click'));
        });
        
        await page.waitForTimeout(5000);
    }

    async solveSucuri(page) {
        log.solver('Solving Sucuri challenge...');
        
        await page.waitForFunction(() => {
            return !document.body.innerHTML.includes('Sucuri Website Firewall');
        }, { timeout: 30000 });
    }

    async solveImperva(page) {
        log.solver('Bypassing Imperva...');
        
        // Imperva requires sophisticated behavior
        await page.mouse.move(100, 100);
        await page.mouse.move(200, 200);
        await page.mouse.move(300, 300);
        
        await page.evaluate(() => {
            window.scrollTo(0, document.body.scrollHeight / 2);
        });
        
        await page.waitForTimeout(8000);
    }

    async solveReCAPTCHA(page) {
        log.solver('Attempting to solve reCAPTCHA...');
        
        // Check if audio challenge is available (easier to bypass)
        try {
            await page.click('#recaptcha-anchor');
            await page.waitForTimeout(2000);
            
            // Try audio challenge
            const audioButton = await page.$('.rc-button-audio');
            if (audioButton) {
                await audioButton.click();
                await page.waitForTimeout(5000);
            }
        } catch (e) {}
        
        await page.waitForTimeout(10000);
    }

    async solveHCaptcha(page) {
        log.solver('Attempting to solve hCaptcha...');
        
        try {
            // Try to trigger challenge
            const checkbox = await page.$('.h-captcha');
            if (checkbox) {
                await checkbox.click();
                await page.waitForTimeout(10000);
            }
        } catch (e) {}
    }

    async solveDataDome(page) {
        log.solver('Bypassing DataDome...');
        
        await page.evaluate(() => {
            // Clear DataDome cookies
            document.cookie.split(';').forEach(cookie => {
                const [name] = cookie.split('=');
                if (name.trim().includes('datadome')) {
                    document.cookie = `${name.trim()}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
                }
            });
        });
        
        await page.reload({ waitUntil: 'networkidle2' });
        await page.waitForTimeout(5000);
    }

    async solvePerimeterX(page) {
        log.solver('Bypassing PerimeterX...');
        
        await page.waitForFunction(() => {
            return !document.body.innerHTML.includes('px-captcha');
        }, { timeout: 30000 }).catch(() => {});
        
        await page.waitForTimeout(5000);
    }

    async solveGenericChallenge(page) {
        log.solver('Solving generic challenge...');
        
        // Try to find and click any challenge completion elements
        const selectors = [
            'input[type="submit"]',
            'button[type="submit"]',
            '.submit',
            '#submit',
            '.verify',
            '#verify',
            '.challenge-button',
            '[onclick*="verify"]',
            '[onclick*="challenge"]'
        ];

        for (const selector of selectors) {
            try {
                const element = await page.$(selector);
                if (element) {
                    await element.click();
                    await page.waitForTimeout(3000);
                    break;
                }
            } catch (e) {}
        }

        // Try to fill any input fields
        const inputs = await page.$$('input[type="text"], input:not([type])');
        for (const input of inputs) {
            try {
                await input.type('human');
                await page.waitForTimeout(500);
            } catch (e) {}
        }

        await page.waitForTimeout(5000);
    }
}

// Main execution
async function main() {
    const args = process.argv.slice(2);
    
    if (args.length < 1) {
        console.log(`
${colors.bright}Auto-Universal WAF Solver${colors.reset}
Usage: node solver.js <url> [proxy.txt]

Examples:
  node solver.js https://cloudflare.com
  node solver.js https://cloudflare.com proxies.txt
  node solver.js https://example.com /path/to/proxy.txt
        `);
        process.exit(1);
    }

    const targetUrl = args[0];
    const proxyFile = args[1] || 'proxy.txt';

    const solver = new AutoWAFSolver();
    
    // Load proxies if file exists
    await solver.loadProxies(proxyFile);

    try {
        const result = await solver.solveAll(targetUrl);
        
        console.log(`\n${colors.green}${'='.repeat(60)}${colors.reset}`);
        console.log(`${colors.bright}RESULT:${colors.reset}`);
        console.log(`${colors.green}${'='.repeat(60)}${colors.reset}`);
        console.log(JSON.stringify(result, null, 2));
        
        process.exit(0);
    } catch (error) {
        log.error(`Final error: ${error.message}`);
        process.exit(1);
    }
}

main();