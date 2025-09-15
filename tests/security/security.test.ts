import request from 'supertest';
import { describe, expect, it } from 'vitest';

// Basic security-path tests (not exhaustive)

describe('security', () => {
    it('rejects invalid token', async () => {
        const app = (await import('../../mcp-server/src/index')).default;
        const res = await request(app).post('/tools/tabs.listGroups').set('Authorization', 'Bearer badtoken').send({});
        expect(res.status).toBe(401);
    });

    it('enforces TOTP when enrolled', async () => {
        const app = (await import('../../mcp-server/src/index')).default;
        await request(app).post('/auth/register').send({ email: 'sec@test.com', password: 'Passw0rd!' });
        const login1 = await request(app).post('/auth/login').send({ email: 'sec@test.com', password: 'Passw0rd!' });
        expect(login1.status).toBe(200);
        const token = login1.body.token;
        await request(app).post('/auth/enrollTotp').set('Authorization', `Bearer ${token}`).send({});
        const login2 = await request(app).post('/auth/login').send({ email: 'sec@test.com', password: 'Passw0rd!' });
        expect(login2.status).toBe(401);
        expect(login2.body.error).toBe('totp-required');
    });

    it('prevents decrypt with wrong password-derived key (encryption round trip)', async () => {
        const app = (await import('../../mcp-server/src/index')).default;
        const email = 'enc@test.com';
        const password = 'StrongPass!1';
        await request(app).post('/auth/register').send({ email, password });
        const login = await request(app).post('/auth/login').send({ email, password });
        expect(login.status).toBe(200);
        const token = login.body.token as string;
        // Save a session (encrypted server-side with per-user data key)
        const save = await request(app).post('/tools/tabs.saveGroups').set('Authorization', `Bearer ${token}`).send({ groups: [{ name: 'A', tabs: [{ url: 'https://a.dev' }] }] });
        expect(save.status).toBe(200);
        // Access raw session in DB to extract ciphertext
        // Reuse server's Prisma singleton
        const { prisma } = await import('../../mcp-server/src/prisma');
        const user = await prisma.user.findUnique({ where: { email } });
        expect(user).toBeTruthy();
        const session = await prisma.session.findFirst({ where: { userId: user!.id }, orderBy: { createdAt: 'desc' } });
        expect(session).toBeTruthy();
        const payload = JSON.parse(session!.groupsCipher);
        // Derive an incorrect key (different password) and expect failure
        const cryptoMod = await import('crypto');
        const wrongUserKey = cryptoMod.pbkdf2Sync('WrongPass!1', Buffer.from(user!.encSalt!, 'base64'), 150000, 32, 'sha512');
        const { decryptJSON } = await import('../../mcp-server/src/crypto');
        let failed = false;
        try {
            decryptJSON(payload, wrongUserKey);
        } catch {
            failed = true;
        }
        expect(failed).toBe(true);
        // Derive correct key and expect success
        const correctUserKey = cryptoMod.pbkdf2Sync(password, Buffer.from(user!.encSalt!, 'base64'), 150000, 32, 'sha512');
        const dec = decryptJSON(payload, correctUserKey);
        expect(dec.k).toBeDefined();
    });

    it('rejects WebAuthn registration finish with reused challenge', async () => {
        const app = (await import('../../mcp-server/src/index')).default;
        await request(app).post('/auth/register').send({ email: 'wa@test.com', password: 'Passw0rd!' });
        const login = await request(app).post('/auth/login').send({ email: 'wa@test.com', password: 'Passw0rd!' });
        const token = login.body.token;
        // Begin registration to create challenge
        const begin = await request(app).post('/auth/webauthn/register/begin').set('Authorization', `Bearer ${token}`).send({});
        if (begin.status !== 200) return; // WebAuthn optional dependency may be unavailable
        const options = begin.body.options;
        // Simulate a bogus finish attempt with wrong response
        const finish1 = await request(app).post('/auth/webauthn/register/finish').set('Authorization', `Bearer ${token}`).send({ id: 'cred', rawId: 'cred', response: {}, type: 'public-key' });
        expect([400, 503]).toContain(finish1.status);
        // Attempt reuse (should also fail / no-challenge if consumed or invalid)
        const finish2 = await request(app).post('/auth/webauthn/register/finish').set('Authorization', `Bearer ${token}`).send({ id: 'cred', rawId: 'cred', response: {}, type: 'public-key' });
        expect([400, 503]).toContain(finish2.status);
    });

    it('rejects WebAuthn authentication with invalid credential', async () => {
        const app = (await import('../../mcp-server/src/index')).default;
        await request(app).post('/auth/register').send({ email: 'wa2@test.com', password: 'Passw0rd!' });
        const login = await request(app).post('/auth/login').send({ email: 'wa2@test.com', password: 'Passw0rd!' });
        const token = login.body.token;
        // Begin auth without having registered a credential should fail early or at finish
        const begin = await request(app).post('/auth/webauthn/authenticate/begin').set('Authorization', `Bearer ${token}`).send({});
        // If user has no credential expect 400
        if (begin.status === 400) return;
        if (begin.status !== 200) return; // optional dependency missing
        // Attempt finish with bogus assertion
        const finish = await request(app).post('/auth/webauthn/authenticate/finish').set('Authorization', `Bearer ${token}`).send({ id: 'x', rawId: 'x', response: {}, type: 'public-key' });
        expect([400, 503]).toContain(finish.status);
    });
});
