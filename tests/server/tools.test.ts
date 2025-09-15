import request from 'supertest';
import { beforeAll, describe, expect, it } from 'vitest';
import '../setup';

let token: string;
// Prisma client is instantiated within server; no direct import needed here

describe('MCP tools', () => {
    beforeAll(async () => {
        const app = (await import('../../mcp-server/src/index')).default;
    });

    it('registers and logs in user', async () => {
        const app = (await import('../../mcp-server/src/index')).default;
        await request(app).post('/auth/register').send({ email: 'a@test.com', password: 'Passw0rd!' });
        const login = await request(app).post('/auth/login').send({ email: 'a@test.com', password: 'Passw0rd!' });
        expect(login.status).toBe(200);
        token = login.body.token;
    });

    it('saves and loads session', async () => {
        const app = (await import('../../mcp-server/src/index')).default;
        const session = { id: 's1', createdAt: new Date().toISOString(), device: 'test', groups: [{ id: 'g1', label: 'Group', category: 'test', tabIds: ['t1'] }] };
        const save = await request(app).post('/tools/tabs.saveGroups').set('Authorization', `Bearer ${token}`).send({ session });
        expect(save.status).toBe(200);
        const load = await request(app).post('/tools/tabs.loadGroups').set('Authorization', `Bearer ${token}`).send({ id: save.body.id });
        expect(load.status).toBe(200);
        expect(load.body.groups.length).toBe(1);
    });
});
