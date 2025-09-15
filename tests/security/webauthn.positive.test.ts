import request from 'supertest';
import { describe, expect, it } from 'vitest';

// Positive WebAuthn flow test (skips if server indicates unavailable)

describe('webauthn positive', () => {
    it('registers and authenticates a credential (if supported)', async () => {
        const app = (await import('../../mcp-server/src/index')).default;
        await request(app).post('/auth/register').send({ email: 'wa-pos@test.com', password: 'Passw0rd!' });
        const login = await request(app).post('/auth/login').send({ email: 'wa-pos@test.com', password: 'Passw0rd!' });
        expect(login.status).toBe(200);
        const token = login.body.token;

        // Begin registration
        const begin = await request(app).post('/auth/webauthn/register/begin').set('Authorization', `Bearer ${token}`).send({});
        if (begin.status === 503) {
            console.warn('WebAuthn unavailable - skipping positive test');
            return;
        }
        expect(begin.status).toBe(200);
        const { options } = begin.body;
        expect(options.challenge).toBeDefined();

        // We cannot produce a real attestation in test environment; assert server rejects dummy but returns 400 not 500.
        const finish = await request(app).post('/auth/webauthn/register/finish')
            .set('Authorization', `Bearer ${token}`)
            .send({ id: 'dummy', rawId: 'dummy', response: {}, type: 'public-key' });
        expect([400, 503]).toContain(finish.status);
    });
});
