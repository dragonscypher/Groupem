import request from 'supertest';
import { beforeAll, describe, expect, it } from 'vitest';

let app: any; let token: string;

describe('server integration', () => {
    beforeAll(async () => {
        app = (await import('../../mcp-server/src/index')).default;
        await request(app).post('/auth/register').send({ email: 'int@test.com', password: 'Passw0rd!' });
        const login = await request(app).post('/auth/login').send({ email: 'int@test.com', password: 'Passw0rd!' });
        token = login.body.token;
    });

    it('saves and lists session', async () => {
        const body = { session: { id: 'sx', createdAt: new Date().toISOString(), device: 'int', groups: [{ id: 'g1', label: 'L', category: 'c', tabIds: ['t1', 't2'] }] } };
        const save = await request(app).post('/tools/tabs.saveGroups').set('Authorization', `Bearer ${token}`).send(body);
        expect(save.status).toBe(200);
        const list = await request(app).post('/tools/tabs.listGroups').set('Authorization', `Bearer ${token}`).send({});
        expect(list.status).toBe(200);
        expect(list.body.items.length).toBeGreaterThan(0);
    });

    it('storage put/get/search', async () => {
        const put = await request(app).post('/tools/storage.put').set('Authorization', `Bearer ${token}`).send({ key: 'k1', value: { a: 1 }, tags: ['x'] });
        expect(put.body.ok).toBe(true);
        const get = await request(app).post('/tools/storage.get').set('Authorization', `Bearer ${token}`).send({ key: 'k1' });
        expect(get.body.value.a).toBe(1);
        const search = await request(app).post('/tools/storage.search').set('Authorization', `Bearer ${token}`).send({ query: 'k' });
        expect(search.body.keys).toContain('k1');
    });

    it('embeddings index/query', async () => {
        const index = await request(app).post('/tools/embeddings.index').set('Authorization', `Bearer ${token}`).send({ objects: [{ id: 'o1', text: 'hello world' }, { id: 'o2', text: 'world test' }] });
        expect(index.body.ok).toBe(true);
        const query = await request(app).post('/tools/embeddings.query').set('Authorization', `Bearer ${token}`).send({ text: 'hello', topK: 2 });
        expect(Array.isArray(query.body)).toBe(true);
    });
});
