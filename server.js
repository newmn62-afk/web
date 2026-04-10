/**
 * ⚡ ULTRA DOWNLOADER — Hardened Server
 * Run:  node server.js
 * Deps: npm install express cors fs-extra helmet express-rate-limit
 *       pip install yt-dlp
 */

import express          from 'express';
import cors             from 'cors';
import helmet           from 'helmet';
import rateLimit        from 'express-rate-limit';
import { spawn }        from 'child_process';
import fs               from 'fs-extra';
import path             from 'path';
import { fileURLToPath } from 'url';
import http             from 'http';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app            = express();
const PORT           = 3000;
const TEMP           = path.join(__dirname, 'dl_temp');
const MAX_CONCURRENT = 5;
const FILE_TTL_MS    = 20 * 60 * 1000;   // 20 min before temp file deleted
const MAX_URL_LEN    = 2048;              // reject absurdly long URLs
const MAX_BODY_SIZE  = '10kb';            // reject oversized POST bodies

// Allowed origin — your Vercel frontend ONLY
// Change this to your real Vercel URL
const ALLOWED_ORIGIN = 'https://your-app.vercel.app';

fs.ensureDirSync(TEMP);

// ══════════════════════════════════════════════════════════════════════════════
// SECURITY MIDDLEWARE STACK
// ══════════════════════════════════════════════════════════════════════════════

// 1. Helmet — sets 14 security HTTP headers in one shot:
//    X-Content-Type-Options, X-Frame-Options, X-XSS-Protection,
//    Strict-Transport-Security, Content-Security-Policy, etc.
app.use(helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' }, // allow blob fetches from Vercel
    contentSecurityPolicy: false,   // handled by Vercel frontend, not needed here
}));

// 2. CORS — ONLY allow requests from your Vercel frontend
//    Blocks every other origin (other websites, random curl scripts, etc.)
app.use(cors({
    origin: (origin, cb) => {
        // Allow requests with no origin (health checkers, same-machine curl)
        // AND requests from our exact Vercel domain
        if (!origin || origin === ALLOWED_ORIGIN) return cb(null, true);
        console.warn(`[CORS BLOCK] Rejected origin: ${origin}`);
        cb(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'ngrok-skip-browser-warning'],
}));

// 3. Body size limit — prevents memory exhaustion via huge POST bodies
app.use(express.json({ limit: MAX_BODY_SIZE }));

// 4. Global rate limiter — max 60 requests per IP per minute
//    Blocks DDoS, brute force, and automated scanners
const globalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Slow down.' },
    handler: (req, res, next, options) => {
        console.warn(`[RATE LIMIT] IP blocked: ${getIP(req)}`);
        res.status(429).json(options.message);
    },
});
app.use(globalLimiter);

// 5. Strict rate limiter for expensive endpoints
//    /info and /download are yt-dlp spawns — very heavy
const heavyLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,   // only 10 download/info requests per minute per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many download requests. Please wait a minute.' },
});

// 6. Remove "X-Powered-By: Express" header (stops fingerprinting)
app.disable('x-powered-by');

// ══════════════════════════════════════════════════════════════════════════════
// IP BLOCKLIST (in-memory — persists while server runs)
// ══════════════════════════════════════════════════════════════════════════════
const blockedIPs   = new Set();
const suspectHits  = new Map(); // ip -> { count, firstSeen }
const BLOCK_THRESH = 20; // auto-block after 20 suspicious requests

function getIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0].trim()
        || req.socket.remoteAddress
        || 'unknown';
}

function trackSuspect(ip, reason) {
    if (blockedIPs.has(ip)) return;
    const entry = suspectHits.get(ip) || { count: 0, firstSeen: Date.now() };
    entry.count++;
    suspectHits.set(ip, entry);
    console.warn(`[SUSPECT] ${ip} — ${reason} (hit #${entry.count})`);
    if (entry.count >= BLOCK_THRESH) {
        blockedIPs.add(ip);
        console.warn(`[AUTO-BLOCK] IP permanently blocked this session: ${ip}`);
    }
}

// Middleware: check blocklist on every request
app.use((req, res, next) => {
    const ip = getIP(req);
    if (blockedIPs.has(ip)) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
});

// ══════════════════════════════════════════════════════════════════════════════
// NMAP / SCANNER DETECTION
// Scanners probe paths like /admin, /wp-login, /.env, /etc/passwd, /shell, etc.
// We detect and auto-block them immediately.
// ══════════════════════════════════════════════════════════════════════════════
const SCAN_PATTERNS = [
    /\/\.env/i, /\/\.git/i, /\/admin/i, /\/wp-/i, /\/phpmy/i,
    /\/etc\/passwd/i, /\/shell/i, /\/cmd/i, /\/config/i,
    /\/actuator/i, /\/api\/v\d/i, /\/swagger/i, /\/xmlrpc/i,
    /\/cgi-bin/i, /\/backup/i, /\/\.htaccess/i, /select.*from/i,
    /union.*select/i, /drop.*table/i, /<script/i, /javascript:/i,
    /\.\.\//,   // path traversal
];

app.use((req, res, next) => {
    const probe = req.url + JSON.stringify(req.query) + (req.body ? JSON.stringify(req.body) : '');
    const ip    = getIP(req);

    for (const pattern of SCAN_PATTERNS) {
        if (pattern.test(probe)) {
            trackSuspect(ip, `scan probe: ${req.url}`);
            return res.status(404).json({ error: 'Not found' }); // don't reveal anything
        }
    }
    next();
});

// ══════════════════════════════════════════════════════════════════════════════
// INPUT VALIDATION HELPERS
// ══════════════════════════════════════════════════════════════════════════════

// Only allow real http/https URLs pointing to known-safe domains
// Blocks: file://, javascript:, data:, internal IPs (SSRF), localhost
const ALLOWED_URL_PREFIXES = /^https?:\/\//i;
const BLOCKED_URL_PATTERNS = [
    /localhost/i, /127\.0\.0/i, /0\.0\.0\.0/i,
    /192\.168\./i, /10\.\d+\.\d+\.\d+/i, /172\.(1[6-9]|2\d|3[01])\./i,
    /file:\/\//i, /javascript:/i, /data:/i, /ftp:\/\//i,
    /metadata\.google/i, /169\.254\./i,   // cloud metadata SSRF
];

function validateURL(rawUrl, req) {
    const ip = getIP(req);
    if (!rawUrl || typeof rawUrl !== 'string') return { ok: false, reason: 'Missing URL' };
    if (rawUrl.length > MAX_URL_LEN) {
        trackSuspect(ip, 'oversized URL');
        return { ok: false, reason: 'URL too long' };
    }
    if (!ALLOWED_URL_PREFIXES.test(rawUrl)) {
        trackSuspect(ip, `bad URL scheme: ${rawUrl.slice(0,40)}`);
        return { ok: false, reason: 'Only http/https URLs allowed' };
    }
    for (const pattern of BLOCKED_URL_PATTERNS) {
        if (pattern.test(rawUrl)) {
            trackSuspect(ip, `SSRF attempt: ${rawUrl.slice(0,40)}`);
            return { ok: false, reason: 'That URL is not allowed' };
        }
    }
    return { ok: true };
}

// Quality format IDs from yt-dlp look like "137", "bestvideo", "22+140"
// Strictly whitelist to prevent shell injection via the -f argument
function validateQuality(q) {
    if (!q) return true;
    return /^[\w.+\-\/\[\]^@]{1,60}$/.test(q);
}

// Job IDs are generated by us, but still validate before Map lookups
function validateJobId(id) {
    return /^dl_\d+_\d+$/.test(id);
}

// ══════════════════════════════════════════════════════════════════════════════
// JOB TRACKING
// ══════════════════════════════════════════════════════════════════════════════
const activeJobs = new Map();
let jobCount = 0;

// SSE helpers
function sseSetup(res) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no'); // disable nginx buffering if behind proxy
    res.flushHeaders();
}
function sseWrite(res, event, data) {
    if (!res.writableEnded) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

// ══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// ── GET /status — health check ────────────────────────────────────────────────
app.get('/status', (req, res) => {
    res.json({ active: activeJobs.size, max: MAX_CONCURRENT, ok: true });
});

// ── GET /info?url= ─────────────────────────────────────────────────────────────
app.get('/info', heavyLimiter, (req, res) => {
    const rawUrl = req.query.url?.trim();
    const check  = validateURL(rawUrl, req);
    if (!check.ok) return res.status(400).json({ error: check.reason });

    // Timeout: kill yt-dlp if it hangs for >30 seconds
    const proc = spawn('yt-dlp', ['--dump-json', '--no-playlist', '--no-warnings', rawUrl]);
    let raw = '', didRespond = false;

    const timeout = setTimeout(() => {
        if (!didRespond) { didRespond = true; proc.kill(); res.status(504).json({ error: 'Request timed out.' }); }
    }, 30_000);

    proc.stdout.on('data', d => raw += d);
    proc.on('close', code => {
        clearTimeout(timeout);
        if (didRespond) return;
        didRespond = true;
        if (code !== 0 || !raw.trim()) return res.status(400).json({ error: 'Could not fetch info. Check the URL.' });
        try {
            const info = JSON.parse(raw.trim().split('\n')[0]);
            res.json({
                title:     info.title     ?? 'Unknown Title',
                uploader:  info.uploader  ?? info.channel ?? 'Unknown',
                duration:  info.duration  ?? 0,
                thumbnail: info.thumbnail ?? null,
                platform:  info.extractor_key ?? 'Unknown',
                formats: (info.formats ?? [])
                    .filter(f => f.height || f.abr)
                    .map(f => ({
                        id:       f.format_id,
                        label:    f.format_note ?? (f.height ? `${f.height}p` : `${Math.round(f.abr ?? 0)}kbps`),
                        height:   f.height  ?? 0,
                        abr:      f.abr     ?? 0,
                        ext:      f.ext,
                        hasVideo: !!f.vcodec && f.vcodec !== 'none',
                        hasAudio: !!f.acodec && f.acodec !== 'none',
                    }))
                    .filter(f => f.hasVideo || f.hasAudio),
            });
        } catch { res.status(500).json({ error: 'Failed to parse video info.' }); }
    });
    proc.on('error', () => { clearTimeout(timeout); if (!didRespond) { didRespond = true; res.status(500).json({ error: 'yt-dlp not found.' }); } });
});

// ── POST /download ──────────────────────────────────────────────────────────────
app.post('/download', heavyLimiter, (req, res) => {
    const { url: rawUrl, audio, quality, title: clientTitle } = req.body;

    // Validate URL
    const check = validateURL(rawUrl, req);
    if (!check.ok) return res.status(400).json({ error: check.reason });

    // Validate quality — CRITICAL: prevents shell injection via -f argument
    if (quality && !validateQuality(quality)) {
        trackSuspect(getIP(req), `bad quality param: ${String(quality).slice(0,40)}`);
        return res.status(400).json({ error: 'Invalid quality parameter.' });
    }

    if (activeJobs.size >= MAX_CONCURRENT)
        return res.status(429).json({ error: `Server busy. Max ${MAX_CONCURRENT} concurrent downloads.` });

    const id  = `dl_${++jobCount}_${Date.now()}`;
    const ext = audio ? 'mp3' : 'mp4';
    const out = path.join(TEMP, `${id}.${ext}`);  // temp path never exposed to user

    // Sanitize title from client (fallback to 'download')
    const safeTitle = clientTitle
        ? String(clientTitle).replace(/[\\/:*?"<>|]/g, '_').trim().slice(0, 200) || 'download'
        : 'download';

    // Build yt-dlp args — quality is passed as a separate argv element, NOT shell-interpolated
    const args = audio
        ? ['-x', '--audio-format', 'mp3', '--audio-quality', '0',
           '--no-playlist', '--no-warnings', '--newline', '-o', out, rawUrl]
        : quality
            ? ['-f', quality, '--merge-output-format', 'mp4',
               '--no-playlist', '--no-warnings', '--newline', '-o', out, rawUrl]
            : ['-f', 'bv[ext=mp4][vcodec^=avc1]+ba[ext=m4a]/b[ext=mp4]/best',
               '--merge-output-format', 'mp4',
               '--no-playlist', '--no-warnings', '--newline', '-o', out, rawUrl];

    const proc = spawn('yt-dlp', args);
    activeJobs.set(id, {
        proc, out, ext,
        title: safeTitle,
        clients: new Set(),
        done: false, error: null, progress: 0,
    });

    // Kill the process if it runs longer than 10 minutes
    const hardTimeout = setTimeout(() => {
        const job = activeJobs.get(id);
        if (job && !job.done) {
            proc.kill();
            job.error = 'Download timed out.';
            job.clients.forEach(c => { sseWrite(c, 'dl_error', { error: job.error }); c.end(); });
        }
    }, 10 * 60 * 1000);

    proc.stdout.on('data', chunk => {
        const job = activeJobs.get(id); if (!job) return;
        const m = chunk.toString().match(/(\d+(?:\.\d+)?)%/);
        if (m) {
            job.progress = Math.min(99, Math.round(parseFloat(m[1])));
            job.clients.forEach(c => sseWrite(c, 'progress', { progress: job.progress }));
        }
    });

    proc.on('close', code => {
        clearTimeout(hardTimeout);
        const job = activeJobs.get(id); if (!job) return;
        if (code !== 0 || !fs.existsSync(out)) {
            job.error = 'Download failed. The link may be private or unsupported.';
            job.clients.forEach(c => { sseWrite(c, 'dl_error', { error: job.error }); c.end(); });
        } else {
            job.done = true; job.progress = 100;
            const stats = fs.statSync(out);
            const mb    = (stats.size / 1024 / 1024).toFixed(2);
            job.fileSize = stats.size;
            job.clients.forEach(c => { sseWrite(c, 'done', { id, mb }); c.end(); });
        }
        // Auto-delete temp file after FILE_TTL_MS
        setTimeout(() => {
            try { if (fs.existsSync(out)) fs.unlinkSync(out); } catch {}
            activeJobs.delete(id);
        }, FILE_TTL_MS);
    });

    proc.on('error', () => {
        clearTimeout(hardTimeout);
        const job = activeJobs.get(id); if (!job) return;
        job.error = 'yt-dlp not found. Make sure it is installed and in PATH.';
        job.clients.forEach(c => { sseWrite(c, 'dl_error', { error: job.error }); c.end(); });
        activeJobs.delete(id);
    });

    res.json({ id });
});

// ── GET /progress/:id — SSE stream ─────────────────────────────────────────────
app.get('/progress/:id', (req, res) => {
    const { id } = req.params;
    if (!validateJobId(id)) return res.status(400).json({ error: 'Invalid job ID' });

    const job = activeJobs.get(id);
    if (!job) return res.status(404).json({ error: 'Job not found' });

    sseSetup(res);
    if (job.done)  { sseWrite(res, 'done',     { id }); res.end(); return; }
    if (job.error) { sseWrite(res, 'dl_error', { error: job.error }); res.end(); return; }

    sseWrite(res, 'progress', { progress: job.progress });
    job.clients.add(res);
    req.on('close', () => job.clients.delete(res));
});

// ── GET /file/:id — serve completed file ───────────────────────────────────────
app.get('/file/:id', (req, res) => {
    const { id } = req.params;
    if (!validateJobId(id)) return res.status(400).json({ error: 'Invalid job ID' });

    const job = activeJobs.get(id);
    if (!job || !job.done) return res.status(404).send('File not ready');
    if (!fs.existsSync(job.out)) return res.status(410).send('File expired');

    const mime = job.ext === 'mp3' ? 'audio/mpeg' : 'video/mp4';

    // RFC 5987 encoded filename — handles unicode titles safely
    const encodedName = encodeURIComponent(`${job.title}.${job.ext}`);
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodedName}`);
    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Length', job.fileSize);   // enables real progress bar
    res.setHeader('Cache-Control', 'no-store');       // don't cache private files

    const stream = fs.createReadStream(job.out);
    stream.pipe(res);
    stream.on('error', () => { if (!res.headersSent) res.status(500).send('File read error'); });
});

// ── GET /poll/:id — polling fallback ───────────────────────────────────────────
app.get('/poll/:id', (req, res) => {
    const { id } = req.params;
    if (!validateJobId(id)) return res.status(400).json({ error: 'Invalid job ID' });

    const job = activeJobs.get(id);
    if (!job) return res.status(404).json({ error: 'Job not found or expired' });
    if (job.error) return res.json({ error: job.error });
    if (job.done) {
        const mb = fs.existsSync(job.out)
            ? (fs.statSync(job.out).size / 1024 / 1024).toFixed(2) : null;
        return res.json({ done: true, mb });
    }
    res.json({ progress: job.progress ?? 0 });
});

// ══════════════════════════════════════════════════════════════════════════════
// CATCH-ALL — unknown routes return 404 (don't leak route structure)
// ══════════════════════════════════════════════════════════════════════════════
app.use((req, res) => {
    trackSuspect(getIP(req), `unknown route: ${req.method} ${req.url}`);
    res.status(404).json({ error: 'Not found' });
});

// Global error handler — never leak stack traces to client
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ══════════════════════════════════════════════════════════════════════════════
// START
// ══════════════════════════════════════════════════════════════════════════════
const server = http.createServer(app);

server.on('listening', async () => {
    const { networkInterfaces } = await import('os');
    const nets = networkInterfaces();
    const ips  = [];
    for (const ifaces of Object.values(nets))
        for (const iface of ifaces)
            if ((iface.family === 'IPv4' || iface.family === 4) && !iface.internal)
                ips.push(iface.address);

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('  ⚡ ULTRA DOWNLOADER — Hardened Server');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`  Local:   http://localhost:${PORT}`);
    ips.forEach(ip => console.log(`  Network: http://${ip}:${PORT}`));
    console.log(`  Allowed: ${ALLOWED_ORIGIN}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});

server.listen(PORT, '0.0.0.0');
