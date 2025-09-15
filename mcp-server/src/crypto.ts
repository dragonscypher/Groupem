import * as crypto from 'crypto';

export function deriveUserKey(password: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(password, salt, 120000, 32, 'sha512');
}

export function encryptJSON(obj: any, key: Buffer): { cipher: string; iv: string } {
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('invalid-key');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const json = Buffer.from(JSON.stringify(obj), 'utf8');
    const enc = Buffer.concat([cipher.update(json), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { cipher: Buffer.concat([enc, tag]).toString('base64'), iv: iv.toString('base64') };
}

export function decryptJSON(payload: { cipher: string; iv: string }, key: Buffer): any {
    if (!payload?.cipher || !payload?.iv) throw new Error('invalid-payload');
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('invalid-key');
    const data = Buffer.from(payload.cipher, 'base64');
    const iv = Buffer.from(payload.iv, 'base64');
    const enc = data.slice(0, data.length - 16);
    const tag = data.slice(data.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    return JSON.parse(dec.toString('utf8'));
}
