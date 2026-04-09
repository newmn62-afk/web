/**
 * ⚡ ULTRA DOWNLOADER — Local Web Server
 * Run: node server.js
 * Then open: http://YOUR_LOCAL_IP:3000 on any WiFi device
 *
 * Requirements: npm install express cors
 *               yt-dlp must be installed (pip install yt-dlp)
 */

import express  from 'express';
import cors     from 'cors';
import { spawn } from 'child_process';
import fs       from 'fs-extra';
import path     from 'path';
import { fileURLToPath } from 'url';
import http     from 'http';
import { createRequire } from 'module';

const require    = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = 3000;
const TEMP = path.join(__dirname, 'dl_temp');
const MAX_CONCURRENT = 5;

fs.ensureDirSync(TEMP);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Track active downloads
const activeJobs = new Map(); // id -> { proc, clients: Set }
let jobCount = 0;

// ── SSE helper ────────────────────────────────────────────────────────────────
function sseSetup(res) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();
}
function sseWrite(res, event, data) {
    if (!res.writableEnded) {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    }
}

// ── GET /info?url= — fetch video metadata ─────────────────────────────────────
app.get('/info', (req, res) => {
    const url = req.query.url?.trim();
    if (!url) return res.status(400).json({ error: 'No URL provided' });

    const proc = spawn('yt-dlp', [
        '--dump-json', '--no-playlist', '--no-warnings', url
    ]);
    let raw = '', err = '';
    proc.stdout.on('data', d => raw += d);
    proc.stderr.on('data', d => err += d);
    proc.on('close', code => {
        if (code !== 0 || !raw.trim()) {
            return res.status(400).json({ error: 'Could not fetch info. Check the URL.' });
        }
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
        } catch {
            res.status(500).json({ error: 'Failed to parse video info.' });
        }
    });
});

// ── POST /download — start a download, stream progress via SSE ───────────────
// Returns jobId immediately; client subscribes to /progress/:jobId
app.post('/download', (req, res) => {
    const { url, audio, quality } = req.body;
    if (!url) return res.status(400).json({ error: 'No URL' });
    if (activeJobs.size >= MAX_CONCURRENT)
        return res.status(429).json({ error: `Server busy (max ${MAX_CONCURRENT} concurrent). Try again shortly.` });

    const id  = `dl_${++jobCount}_${Date.now()}`;
    const ext = audio ? 'mp3' : 'mp4';
    const out = path.join(TEMP, `${id}.${ext}`);

    const args = audio
        ? ['-x', '--audio-format', 'mp3', '--audio-quality', '0', '--no-playlist', '--no-warnings', '-o', out, url]
        : quality
            ? ['-f', `${quality}+bestaudio/best[ext=mp4]`, '--merge-output-format', 'mp4', '--no-playlist', '--no-warnings', '-o', out, url]
            : ['-f', 'bv[ext=mp4][vcodec^=avc1]+ba[ext=m4a]/b[ext=mp4]/best', '--merge-output-format', 'mp4', '--no-playlist', '--no-warnings', '-o', out, url];

    const proc = spawn('yt-dlp', [...args, '--newline']);

    // Fetch the video title asynchronously so we can use it as the filename
    let videoTitle = 'download';
    const titleProc = spawn('yt-dlp', ['--print', 'title', '--no-playlist', '--no-warnings', url]);
    let titleRaw = '';
    titleProc.stdout.on('data', d => titleRaw += d);
    titleProc.on('close', () => {
        const t = titleRaw.trim().split('\n')[0];
        if (t) {
            // Sanitize: remove characters that are illegal in filenames
            videoTitle = t.replace(/[\\/:*?"<>|]/g, '_').trim();
            const job = activeJobs.get(id);
            if (job) job.title = videoTitle;
        }
    });

    activeJobs.set(id, { proc, out, ext, title: videoTitle, clients: new Set(), done: false, error: null, progress: 0 });

    proc.stdout.on('data', chunk => {
        const job = activeJobs.get(id);
        if (!job) return;
        const m = chunk.toString().match(/(\d+(?:\.\d+)?)%/);
        if (m) {
            job.progress = Math.min(99, Math.round(parseFloat(m[1])));
            job.clients.forEach(c => sseWrite(c, 'progress', { progress: job.progress }));
        }
    });

    proc.on('close', code => {
        const job = activeJobs.get(id);
        if (!job) return;
        if (code !== 0 || !fs.existsSync(out)) {
            job.error = 'Download failed. The link may be private or unsupported.';
            job.clients.forEach(c => { sseWrite(c, 'dl_error', { error: job.error }); c.end(); });
        } else {
            job.done = true;
            job.progress = 100;
            const mb = (fs.statSync(out).size / 1024 / 1024).toFixed(2);
            job.clients.forEach(c => { sseWrite(c, 'done', { id, mb }); c.end(); });
        }
        // Clean up job after 10 min
        setTimeout(() => {
            try { if (fs.existsSync(out)) fs.unlinkSync(out); } catch {}
            activeJobs.delete(id);
        }, 10 * 60 * 1000);
    });

    proc.on('error', () => {
        const job = activeJobs.get(id);
        if (!job) return;
        job.error = 'yt-dlp not found. Make sure it is installed and in PATH.';
        job.clients.forEach(c => { sseWrite(c, 'dl_error', { error: job.error }); c.end(); });
        activeJobs.delete(id);
    });

    res.json({ id });
});

// ── GET /progress/:id — SSE stream for a download job ─────────────────────────
app.get('/progress/:id', (req, res) => {
    const job = activeJobs.get(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found' });

    sseSetup(res);
    if (job.done) { sseWrite(res, 'done', { id: req.params.id }); res.end(); return; }
    if (job.error) { sseWrite(res, 'error', { error: job.error }); res.end(); return; }

    // Send current progress immediately
    sseWrite(res, 'progress', { progress: job.progress });
    job.clients.add(res);
    req.on('close', () => job.clients.delete(res));
});

// ── GET /file/:id — serve the finished file for download ──────────────────────
app.get('/file/:id', (req, res) => {
    const job = activeJobs.get(req.params.id);
    if (!job || !job.done) return res.status(404).send('File not ready');
    const mime = job.ext === 'mp3' ? 'audio/mpeg' : 'video/mp4';
    const name = `${job.title || 'download'}.${job.ext}`;
    res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
    res.setHeader('Content-Type', mime);
    const stream = fs.createReadStream(job.out);
    stream.pipe(res);
    stream.on('error', () => res.status(500).send('File read error'));
});

// ── GET /poll/:id — polling fallback when SSE disconnects ─────────────────────
// Returns current job state as JSON so the client can stay updated
// even if their SSE connection dropped (phone screen off, brief wifi loss, etc.)
app.get('/poll/:id', (req, res) => {
    const job = activeJobs.get(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found or expired' });
    if (job.error) return res.json({ error: job.error });
    if (job.done) {
        const mb = fs.existsSync(job.out)
            ? (fs.statSync(job.out).size / 1024 / 1024).toFixed(2)
            : null;
        return res.json({ done: true, mb });
    }
    res.json({ progress: job.progress ?? 0 });
});

// ── GET /status — quick health check ──────────────────────────────────────────
app.get('/status', (req, res) => {
    res.json({ active: activeJobs.size, max: MAX_CONCURRENT });
});

// ── Start ──────────────────────────────────────────────────────────────────────
// ── Start ──────────────────────────────────────────────────────────────────────
const server = http.createServer(app);

// We use the 'listening' event to handle the async IP lookups properly
server.on('listening', async () => {
    const { networkInterfaces } = await import('os');
    const nets = networkInterfaces();
    const ips  = [];
    
    for (const ifaces of Object.values(nets)) {
        for (const iface of ifaces) {
            // Check for IPv4 and skip internal (loopback) addresses
            if (iface.family === 'IPv4' || iface.family === 4) {
                if (!iface.internal) ips.push(iface.address);
            }
        }
    }

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('  ⚡ ULTRA DOWNLOADER — Web Server');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`  Local:   http://localhost:${PORT}`);
    ips.forEach(ip => console.log(`  Network: http://${ip}:${PORT}  ← share with WiFi users`));
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});

server.listen(PORT, '0.0.0.0');
