import {
    AuthVerifyTotpInputSchema,
    EmbeddingsIndexInputSchema, EmbeddingsQueryInputSchema,
    ListGroupsInputSchema,
    LoadGroupsInputSchema,
    MergeGroupsInputSchema,
    SaveGroupsInputSchema,
    SessionSchema,
    StorageGetInputSchema,
    StoragePutInputSchema,
    StorageSearchInputSchema
} from '@groupem/shared/dist/models';
import * as argon2 from 'argon2';
import * as cors from 'cors';
import * as crypto from 'crypto';
import * as express from 'express';
import * as fs from 'fs';
import * as jwt from 'jsonwebtoken';
import * as multer from 'multer';
import * as otplib from 'otplib';
import { v4 as uuidv4 } from 'uuid';
import { decryptJSON, encryptJSON } from './crypto';
import { clearDataKey, getDataKey, setDataKey } from './keyCache';
import { prisma } from './prisma';
// Load environment variables (tolerate absence of types)
let dotenv: any; try { dotenv = require('dotenv'); dotenv.config(); } catch { /* ignore */ }
let simplewebauthn: any;
try { simplewebauthn = require('@simplewebauthn/server'); } catch { simplewebauthn = null; }

// Workaround: TS type mismatch for generated delegate property; cast to any
const webAuthnChallenge = (prisma as any).webAuthnChallenge;
// Compatibility wrappers for ESM/CJS interop when using namespace import with esModuleInterop true/false
const expressLib: any = (express as any).default || (express as any);
const corsLib: any = (cors as any).default || (cors as any);
const multerLib: any = (multer as any).default || (multer as any);

const app = expressLib();
app.use(corsLib());
app.use(expressLib.json({ limit: '2mb' }));

const upload = multerLib({ dest: 'uploads/' });

// Root health/info route
app.get('/', (_req: express.Request, res: express.Response) => {
    res.json({ name: 'groupem-mcp', status: 'ok', time: new Date().toISOString(), mlUrl: process.env.ML_URL || 'http://localhost:8000' });
});

// ML service reachability cache
let mlStatus: { reachable: boolean; lastChecked: number; detail?: string } = { reachable: false, lastChecked: 0 };
const ML_URL = process.env.ML_URL || 'http://localhost:8000';

async function checkMl(force = false) {
    const now = Date.now();
    if (!force && now - mlStatus.lastChecked < 15000) return mlStatus; // 15s cache
    try {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), 2500);
        const fetchFn: any = (global as any).fetch || require('node-fetch');
        const r = await fetchFn(`${ML_URL}/health`, { signal: controller.signal });
        clearTimeout(t);
        if (r.ok) {
            const j = await r.json().catch(() => ({}));
            mlStatus = { reachable: true, lastChecked: now, detail: j.status || 'ok' };
        } else {
            mlStatus = { reachable: false, lastChecked: now, detail: `status ${r.status}` };
        }
    } catch (e: any) {
        mlStatus = { reachable: false, lastChecked: now, detail: e?.code || 'error' };
    }
    return mlStatus;
}

app.get('/ml/health', async (_req: express.Request, res: express.Response) => {
    const s = await checkMl();
    res.json({ mlUrl: ML_URL, reachable: s.reachable, detail: s.detail, lastChecked: s.lastChecked });
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

function authMiddleware(req: express.Request, res: express.Response, next: express.NextFunction) {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'missing auth' });
    try {
        const token = auth.split(' ')[1];
        const payload = jwt.verify(token, JWT_SECRET) as any;
        (req as any).userId = payload.sub;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'invalid token' });
    }
}

app.post('/auth/register', async (req: express.Request, res: express.Response) => {
    const { email, password, phone, autoTotp } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'missing' });
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    const enableTotp = !!autoTotp || !!phone; // auto enroll if requested or phone provided
    try {
        const salt = crypto.randomBytes(16);
        const userKey = crypto.pbkdf2Sync(password, salt, 150000, 32, 'sha512');
        const dataKey = crypto.randomBytes(32);
        const { cipher: encKeyCipher, iv: encKeyIv } = encryptJSON({ k: dataKey.toString('base64') }, userKey);
        let totpSecret: string | undefined;
        if (enableTotp) {
            totpSecret = otplib.authenticator.generateSecret();
        }
        const user = await prisma.user.create({
            data: {
                email, // @ts-ignore phone field added in schema
                phone: phone || null, passwordHash: hash, encSalt: salt.toString('base64'), encKeyCipher, encKeyIv, totpSecret
            } as any
        });
        res.json({ id: user.id, totpEnrolled: !!totpSecret, totpSecret });
    } catch (e) {
        res.status(400).json({ error: 'exists' });
    }
});

app.post('/auth/login', async (req: express.Request, res: express.Response) => {
    const { email, password, totp } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: 'invalid' });
    const ok = await argon2.verify(user.passwordHash, password);
    if (!ok) return res.status(401).json({ error: 'invalid' });
    if (user.totpSecret) {
        if (!totp) return res.status(401).json({ error: 'totp-required' });
        const v = otplib.authenticator.check(totp, user.totpSecret);
        if (!v) return res.status(401).json({ error: 'totp-invalid' });
    }
    // Unwrap data key
    if (!user.encSalt || !user.encKeyCipher || !user.encKeyIv) return res.status(500).json({ error: 'encryption-missing' });
    const userKey = crypto.pbkdf2Sync(password, Buffer.from(user.encSalt, 'base64'), 150000, 32, 'sha512');
    const { k } = decryptJSON({ cipher: user.encKeyCipher, iv: user.encKeyIv }, userKey);
    const dataKey = Buffer.from(k, 'base64');
    setDataKey(user.id, dataKey);
    const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '15m' });
    const refresh = jwt.sign({ sub: user.id, type: 'refresh' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, refresh });
});

app.post('/auth/logout', authMiddleware, async (req: express.Request, res: express.Response) => {
    clearDataKey((req as any).userId);
    res.json({ ok: true });
});

app.post('/auth/refresh', async (req: express.Request, res: express.Response) => {
    const { refresh } = req.body;
    try {
        const payload = jwt.verify(refresh, JWT_SECRET) as any;
        if (payload.type !== 'refresh') throw new Error('bad');
        const token = jwt.sign({ sub: payload.sub }, JWT_SECRET, { expiresIn: '15m' });
        res.json({ token });
    } catch (e) {
        res.status(401).json({ error: 'invalid' });
    }
});

app.post('/auth/enrollTotp', authMiddleware, async (req: express.Request, res: express.Response) => {
    const secret = otplib.authenticator.generateSecret();
    const otpauthUrl = otplib.authenticator.keyuri('user', 'Groupem', secret);
    await prisma.user.update({ where: { id: (req as any).userId }, data: { totpSecret: secret } });
    res.json({ secret, otpauthUrl });
});

app.post('/auth/verifyTotp', authMiddleware, async (req: express.Request, res: express.Response) => {
    try {
        const parsed = AuthVerifyTotpInputSchema.parse(req.body);
        const user = await prisma.user.findUnique({ where: { id: (req as any).userId } });
        if (!user?.totpSecret) return res.json({ ok: false });
        const ok = otplib.authenticator.check(parsed.code, user.totpSecret);
        res.json({ ok });
    } catch (e) {
        res.status(400).json({ error: 'bad-input' });
    }
});

// Tabs tools
app.post('/tools/tabs.saveGroups', authMiddleware, async (req: express.Request, res: express.Response) => {
    try {
        const parsed = SaveGroupsInputSchema.parse(req.body);
        const id = uuidv4();
        const dataKey = getDataKey((req as any).userId);
        if (!dataKey) return res.status(401).json({ error: 'no-session-key' });
        const { cipher, iv } = encryptJSON(parsed.session.groups, dataKey);
        await prisma.session.create({ data: { id, userId: (req as any).userId, device: parsed.session.device, groupsCipher: JSON.stringify({ cipher, iv }) } });
        // Persist tab metadata map (flatten groups->tabIds) for restore (placeholder: just store ids array)
        const tabIds = parsed.session.groups.flatMap(g => g.tabIds);
        const metaEnc = encryptJSON({ tabIds }, dataKey);
        await prisma.storageRecord.create({ data: { id: uuidv4(), userId: (req as any).userId, key: `session:${id}:tabs`, valueCipher: JSON.stringify(metaEnc), tags: 'session,tabs' } });
        res.json({ id });
    } catch (e) {
        res.status(400).json({ error: 'bad-input' });
    }
});

app.post('/tools/tabs.loadGroups', authMiddleware, async (req: express.Request, res: express.Response) => {
    try {
        const parsed = LoadGroupsInputSchema.parse(req.body);
        const session = await prisma.session.findUnique({ where: { id: parsed.id } });
        if (!session || session.userId !== (req as any).userId) return res.status(404).json({ error: 'not-found' });
        const dataKey = getDataKey((req as any).userId);
        if (!dataKey) return res.status(401).json({ error: 'no-session-key' });
        const encObj = JSON.parse(session.groupsCipher);
        const groups = decryptJSON(encObj, dataKey);
        const s = { id: session.id, createdAt: session.createdAt.toISOString(), groups, device: session.device };
        SessionSchema.parse(s);
        res.json(s);
    } catch (e) {
        res.status(400).json({ error: 'bad-input' });
    }
});

app.post('/tools/tabs.listGroups', authMiddleware, async (req: express.Request, res: express.Response) => {
    try {
        const parsed = ListGroupsInputSchema.parse(req.body);
        const limit = parsed.limit || 20;
        const cursor = parsed.cursor;
        const items = await prisma.session.findMany({
            where: { userId: (req as any).userId, id: cursor ? { lt: cursor } : undefined },
            orderBy: { id: 'desc' },
            take: limit + 1
        });
        const dataKey = getDataKey((req as any).userId);
        const resp: any[] = [];
        if (dataKey) {
            for (const s of items.slice(0, limit)) {
                try {
                    const encObj = JSON.parse(s.groupsCipher);
                    const groups = decryptJSON(encObj, dataKey);
                    resp.push({ id: s.id, createdAt: s.createdAt.toISOString(), groups, device: s.device });
                } catch { /* ignore */ }
            }
        }
        const nextCursor = items.length > limit ? items[limit].id : undefined;
        res.json({ items: resp, nextCursor });
    } catch (e) {
        res.status(400).json({ error: 'bad-input' });
    }
});

app.post('/tools/tabs.mergeGroups', authMiddleware, async (req: express.Request, res: express.Response) => {
    try {
        const parsed = MergeGroupsInputSchema.parse(req.body);
        const base = await prisma.session.findUnique({ where: { id: parsed.baseId } });
        if (!base || base.userId !== (req as any).userId) return res.status(404).json({ error: 'not-found' });
        const dataKey = getDataKey((req as any).userId);
        if (!dataKey) return res.status(401).json({ error: 'no-session-key' });
        const encObj = JSON.parse(base.groupsCipher);
        const baseGroups = decryptJSON(encObj, dataKey);
        const mergedGroups = [...baseGroups, ...parsed.incoming.groups];
        const { cipher, iv } = encryptJSON(mergedGroups, dataKey);
        await prisma.session.update({ where: { id: base.id }, data: { groupsCipher: JSON.stringify({ cipher, iv }) } });
        res.json({ id: base.id });
    } catch (e) {
        res.status(400).json({ error: 'bad-input' });
    }
});

// Storage tools
app.post('/tools/storage.put', authMiddleware, async (req: express.Request, res: express.Response) => {
    try {
        const parsed = StoragePutInputSchema.parse(req.body);
        const id = uuidv4();
        const dataKey = getDataKey((req as any).userId);
        if (!dataKey) return res.status(401).json({ ok: false, error: 'no-session-key' });
        const { cipher, iv } = encryptJSON(parsed.value, dataKey);
        await prisma.storageRecord.create({ data: { id, userId: (req as any).userId, key: parsed.key, valueCipher: JSON.stringify({ cipher, iv }), tags: (parsed.tags || []).join(',') } });
        res.json({ ok: true });
    } catch (e) {
        res.status(400).json({ ok: false });
    }
});

app.post('/tools/storage.get', authMiddleware, async (req: express.Request, res: express.Response) => {
    try {
        const parsed = StorageGetInputSchema.parse(req.body);
        const record = await prisma.storageRecord.findFirst({ where: { userId: (req as any).userId, key: parsed.key }, orderBy: { createdAt: 'desc' } });
        if (!record) return res.json({});
        const dataKey = getDataKey((req as any).userId);
        if (!dataKey) return res.status(401).json({});
        const encObj = JSON.parse(record.valueCipher);
        const value = decryptJSON(encObj, dataKey);
        res.json({ value });
    } catch (e) {
        res.status(400).json({});
    }
});

app.post('/tools/storage.search', authMiddleware, async (req: express.Request, res: express.Response) => {
    try {
        const parsed = StorageSearchInputSchema.parse(req.body);
        const items = await prisma.storageRecord.findMany({ where: { userId: (req as any).userId, key: { contains: parsed.query } }, take: 50 });
        res.json({ keys: items.map(i => i.key) });
    } catch (e) {
        res.status(400).json({ keys: [] });
    }
});

// Embeddings (simple TF-IDF placeholder logic for now without external ML service)
const embeddingStore = new Map<string, number[]>();

function simpleEmbed(text: string): number[] {
    const words = text.toLowerCase().split(/\W+/).filter(Boolean);
    const freq: Record<string, number> = {};
    for (const w of words) freq[w] = (freq[w] || 0) + 1;
    const keys = Object.keys(freq).sort();
    return keys.map(k => freq[k] / words.length);
}

app.post('/tools/embeddings.index', authMiddleware, async (req: express.Request, res: express.Response) => {
    try {
        const parsed = EmbeddingsIndexInputSchema.parse(req.body);
        for (const obj of parsed.objects) {
            embeddingStore.set(obj.id, simpleEmbed(obj.text));
        }
        res.json({ ok: true });
    } catch (e) {
        console.error('embeddings.index error', e);
        res.status(400).json({ ok: false });
    }
});

app.post('/tools/embeddings.query', authMiddleware, async (req: express.Request, res: express.Response) => {
    try {
        const parsed = EmbeddingsQueryInputSchema.parse(req.body);
        const qVec = simpleEmbed(parsed.text);
        const cosine = (a: number[], b: number[]): number => {
            const len = Math.min(a.length, b.length);
            let dot = 0, na = 0, nb = 0;
            for (let i = 0; i < len; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
            return dot / (Math.sqrt(na) * Math.sqrt(nb) || 1);
        };
        const scores: { objectId: string; score: number }[] = [];
        Array.from(embeddingStore.entries()).forEach(([id, vec]) => {
            scores.push({ objectId: id, score: cosine(qVec, vec) });
        });
        scores.sort((a, b) => b.score - a.score);
        res.json(scores.slice(0, parsed.topK));
    } catch (e) {
        res.status(400).json([]);
    }
});

// Files resource
app.post('/files/upload', authMiddleware, upload.single('file'), async (req: express.Request, res: express.Response) => {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'no-file' });
    const id = uuidv4();
    await prisma.file.create({ data: { id, userId: (req as any).userId, name: file.originalname, mime: file.mimetype, size: file.size, tags: '', blobPath: file.path } });
    res.json({ id });
});

app.get('/files/list', authMiddleware, async (req: express.Request, res: express.Response) => {
    const items = await prisma.file.findMany({ where: { userId: (req as any).userId }, take: 100, orderBy: { createdAt: 'desc' } });
    res.json({ items: items.map(i => ({ id: i.id, name: i.name, mime: i.mime, size: i.size, tags: i.tags.split(',').filter(Boolean), createdAt: i.createdAt.toISOString() })) });
});

app.get('/files/download/:id', authMiddleware, async (req: express.Request, res: express.Response) => {
    const f = await prisma.file.findUnique({ where: { id: req.params.id } });
    if (!f || f.userId !== (req as any).userId) return res.status(404).end();
    res.setHeader('Content-Type', f.mime);
    fs.createReadStream(f.blobPath).pipe(res);
});

// Browser state resource (simplified streaming via SSE)
app.get('/resources/browser_state', authMiddleware, async (req: express.Request, res: express.Response) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();
    const timer = setInterval(async () => {
        const sessions = await prisma.session.findMany({ where: { userId: (req as any).userId }, orderBy: { createdAt: 'desc' }, take: 5 });
        const dataKey = getDataKey((req as any).userId);
        const payload: any[] = [];
        if (dataKey) {
            for (const s of sessions) {
                try {
                    const encObj = JSON.parse(s.groupsCipher);
                    const groups = decryptJSON(encObj, dataKey);
                    payload.push({ id: s.id, createdAt: s.createdAt.toISOString(), groups, device: s.device });
                } catch {
                    payload.push({ id: s.id, createdAt: s.createdAt.toISOString(), groups: [], device: s.device });
                }
            }
        }
        res.write(`data: ${JSON.stringify(payload)}\n\n`);
    }, 5000);
    req.on('close', () => clearInterval(timer));
});

// WebAuthn registration (begin)
app.post('/auth/webauthn/register/begin', authMiddleware, async (req: express.Request, res: express.Response) => {
    if (!simplewebauthn) return res.status(503).json({ error: 'webauthn-unavailable' });
    const userId = (req as any).userId as string;
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: 'user' });
    const rpName = 'Groupem';
    const rpID = 'localhost';
    const origin = 'http://localhost:5173';
    const { generateRegistrationOptions } = simplewebauthn;
    const options = generateRegistrationOptions({
        rpName,
        rpID,
        userID: userId,
        userName: user.email,
        attestationType: 'none',
        authenticatorSelection: { residentKey: 'discouraged', userVerification: 'preferred' },
        excludeCredentials: user.webAuthnCredentialId ? [{ id: Buffer.from(user.webAuthnCredentialId, 'base64'), type: 'public-key' }] : []
    });
    const webAuthnChallenge = (prisma as any).webAuthnChallenge; // delegate cast to bypass TS mismatch
    await webAuthnChallenge.create({ data: { userId, challenge: options.challenge, type: 'registration' } });
    res.json({ options, origin });
});

// WebAuthn registration (finish)
app.post('/auth/webauthn/register/finish', authMiddleware, async (req: express.Request, res: express.Response) => {
    if (!simplewebauthn) return res.status(503).json({ error: 'webauthn-unavailable' });
    const userId = (req as any).userId as string;
    const body = req.body;
    const chal = await webAuthnChallenge.findFirst({ where: { userId, type: 'registration', consumed: false }, orderBy: { createdAt: 'desc' } });
    if (!chal) return res.status(400).json({ error: 'no-challenge' });
    const { verifyRegistrationResponse } = simplewebauthn;
    try {
        const verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge: chal.challenge,
            expectedOrigin: 'http://localhost:5173',
            expectedRPID: 'localhost'
        });
        if (!verification.verified || !verification.registrationInfo) return res.status(400).json({ error: 'verify-failed' });
        const { credentialID, credentialPublicKey } = verification.registrationInfo;
        await prisma.user.update({ where: { id: userId }, data: { webAuthnCredentialId: credentialID.toString('base64'), webAuthnPublicKey: credentialPublicKey.toString('base64') } });
        await webAuthnChallenge.update({ where: { id: chal.id }, data: { consumed: true } });
        res.json({ ok: true });
    } catch (e) {
        res.status(400).json({ error: 'verify-error' });
    }
});

// WebAuthn authentication (begin)
app.post('/auth/webauthn/authenticate/begin', authMiddleware, async (req: express.Request, res: express.Response) => {
    if (!simplewebauthn) return res.status(503).json({ error: 'webauthn-unavailable' });
    const userId = (req as any).userId as string;
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user?.webAuthnCredentialId) return res.status(400).json({ error: 'no-credential' });
    const { generateAuthenticationOptions } = simplewebauthn;
    const options = generateAuthenticationOptions({
        rpID: 'localhost',
        userVerification: 'preferred',
        allowCredentials: [{ id: Buffer.from(user.webAuthnCredentialId, 'base64'), type: 'public-key' }]
    });
    const webAuthnChallenge = (prisma as any).webAuthnChallenge;
    await webAuthnChallenge.create({ data: { userId, challenge: options.challenge, type: 'authentication' } });
    res.json({ options });
});

// WebAuthn authentication (finish)
app.post('/auth/webauthn/authenticate/finish', authMiddleware, async (req: express.Request, res: express.Response) => {
    if (!simplewebauthn) return res.status(503).json({ error: 'webauthn-unavailable' });
    const userId = (req as any).userId as string;
    const body = req.body;
    const chal = await webAuthnChallenge.findFirst({ where: { userId, type: 'authentication', consumed: false }, orderBy: { createdAt: 'desc' } });
    if (!chal) return res.status(400).json({ error: 'no-challenge' });
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user?.webAuthnCredentialId || !user.webAuthnPublicKey) return res.status(400).json({ error: 'no-credential' });
    const { verifyAuthenticationResponse } = simplewebauthn;
    try {
        const verification = await verifyAuthenticationResponse({
            response: body,
            expectedChallenge: chal.challenge,
            expectedOrigin: 'http://localhost:5173',
            expectedRPID: 'localhost',
            authenticator: {
                credentialID: Buffer.from(user.webAuthnCredentialId, 'base64'),
                credentialPublicKey: Buffer.from(user.webAuthnPublicKey, 'base64'),
                counter: 0,
                transports: ['internal']
            }
        });
        if (!verification.verified) return res.status(400).json({ error: 'verify-failed' });
        await webAuthnChallenge.update({ where: { id: chal.id }, data: { consumed: true } });
        res.json({ ok: true });
    } catch (e) {
        res.status(400).json({ error: 'verify-error' });
    }
});

// Dynamic port selection with fallback if in use
async function startServer() {
    const desired = Number(process.env.PORT) || 8080;
    const maxAttempts = 10;
    let port = desired;
    for (let i = 0; i < maxAttempts; i++) {
        try {
            await new Promise<void>((resolve, reject) => {
                const srv = app.listen(port, () => {
                    console.log(`MCP server running on ${port}`);
                    srv.removeAllListeners('error');
                    resolve();
                });
                srv.once('error', (err: any) => {
                    if (err.code === 'EADDRINUSE') {
                        srv.close();
                        reject(err);
                    } else {
                        console.error('Server listen error', err);
                        reject(err);
                    }
                });
            });
            if (port !== desired) {
                console.warn(`Desired port ${desired} in use; started on ${port}`);
            }
            return;
        } catch (e: any) {
            if (e.code === 'EADDRINUSE') {
                port++;
                continue;
            }
            throw e;
        }
    }
    console.error(`Failed to bind any port between ${desired} and ${port}`);
}

if (require.main === module) {
    startServer().then(() => {
        checkMl(true).then(s => {
            if (!s.reachable) {
                console.warn(`ML service unreachable at ${ML_URL}: ${s.detail}`);
            } else {
                console.log(`ML service reachable at ${ML_URL}`);
            }
        });
    }).catch(e => {
        console.error('Fatal server start error', e);
        process.exit(1);
    });
}

export default app;
