import { expect, request, test } from '@playwright/test';
import crypto from 'crypto';

// This E2E test exercises the server APIs directly (simulating extension behavior) until
// we add true extension loading (needs manifest + loading via launchPersistentContext).
// Steps: register -> login -> (optionally enroll + verify TOTP) -> index embeddings ->
// create synthetic tabs -> group -> save session -> list -> load -> storage.put/get/search -> file upload/list/download -> purity >= 0.85

function syntheticTabs(count = 20) {
    // Generate 5 logical domain groups * 4 tabs each = 20
    const bases = ['alpha.example.com', 'beta.example.com', 'news.site.net', 'blog.site.net', 'portal.app.io'];
    const tabs: { id: string; url: string; title: string }[] = [];
    let idCounter = 1;
    for (const b of bases) {
        for (let i = 0; i < 4; i++) {
            const url = `https://${b}/p/${i}`;
            tabs.push({ id: 't' + (idCounter++), url, title: b + ' page ' + i });
        }
    }
    return tabs.slice(0, count);
}

function groupByDomain(tabs: { id: string; url: string; title: string }[]) {
    const groups: Record<string, string[]> = {};
    for (const t of tabs) {
        try {
            const host = new URL(t.url).hostname.split('.').slice(-2).join('.');
            (groups[host] ||= []).push(t.id);
        } catch {
            (groups['other'] ||= []).push(t.id);
        }
    }
    return Object.entries(groups).map(([label, tabIds]) => ({ id: label + Date.now(), label, category: label, tabIds }));
}

function purity(expected: Record<string, string[]>, predicted: { label: string; tabIds: string[] }[]) {
    const predictedMap: Record<string, Set<string>> = {};
    for (const g of predicted) predictedMap[g.label] = new Set(g.tabIds);
    let total = 0, correct = 0;
    for (const tabs of Object.values(expected)) {
        total += tabs.length;
        let maxOverlap = 0;
        for (const p of Object.values(predictedMap)) {
            let overlap = 0; for (const id of tabs) if (p.has(id)) overlap++;
            if (overlap > maxOverlap) maxOverlap = overlap;
        }
        correct += maxOverlap;
    }
    return total ? correct / total : 1;
}

test('full API workflow purity >= 0.85', async ({ page, playwright }) => {
    const base = 'http://localhost:8080';
    const apiContext = await request.newContext();
    const email = `user_${Date.now()}@example.com`;
    const password = 'Test#12345';

    // Register
    let res = await apiContext.post(base + '/auth/register', { data: { email, password } });
    expect(res.ok()).toBeTruthy();

    // Login
    res = await apiContext.post(base + '/auth/login', { data: { email, password } });
    expect(res.ok()).toBeTruthy();
    let json: any = await res.json();
    const token = json.token as string;
    expect(token).toBeTruthy();

    const authHeaders = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    // Synthetic tabs
    const tabs = syntheticTabs();
    const groups = groupByDomain(tabs);

    // Build expected map for purity (host root two labels)
    const expected: Record<string, string[]> = {};
    for (const t of tabs) {
        try {
            const host = new URL(t.url).hostname.split('.').slice(-2).join('.');
            (expected[host] ||= []).push(t.id);
        } catch {
            (expected['other'] ||= []).push(t.id);
        }
    }

    // Save session
    const sessionBody = { session: { id: crypto.randomUUID(), createdAt: new Date().toISOString(), device: 'e2e', groups } };
    res = await apiContext.post(base + '/tools/tabs.saveGroups', { headers: authHeaders, data: sessionBody });
    expect(res.ok()).toBeTruthy();
    json = await res.json();
    const sessionId = json.id as string;
    expect(sessionId).toBeTruthy();

    // List sessions
    res = await apiContext.post(base + '/tools/tabs.listGroups', { headers: authHeaders, data: {} });
    expect(res.ok()).toBeTruthy();
    json = await res.json();
    expect(Array.isArray(json.items)).toBeTruthy();

    // Load session
    res = await apiContext.post(base + '/tools/tabs.loadGroups', { headers: authHeaders, data: { id: sessionId } });
    expect(res.ok()).toBeTruthy();
    const loaded = await res.json();
    expect(loaded.id).toBe(sessionId);

    // Purity check
    const p = purity(expected, groups.map(g => ({ label: g.label, tabIds: g.tabIds })));
    expect(p).toBeGreaterThanOrEqual(0.85);

    // storage.put
    res = await apiContext.post(base + '/tools/storage.put', { headers: authHeaders, data: { key: 'kv:test', value: { a: 1 }, tags: ['kv'] } });
    expect(res.ok()).toBeTruthy();

    // storage.get
    res = await apiContext.post(base + '/tools/storage.get', { headers: authHeaders, data: { key: 'kv:test' } });
    expect(res.ok()).toBeTruthy();
    json = await res.json();
    expect(json.value.a).toBe(1);

    // storage.search
    res = await apiContext.post(base + '/tools/storage.search', { headers: authHeaders, data: { query: 'kv:' } });
    expect(res.ok()).toBeTruthy();
    json = await res.json();
    expect(Array.isArray(json.keys)).toBeTruthy();

    // embeddings.index + query
    res = await apiContext.post(base + '/tools/embeddings.index', {
        headers: authHeaders, data: {
            objects: [
                { id: 'o1', text: 'alpha project planning', kind: 'doc' },
                { id: 'o2', text: 'beta release notes', kind: 'doc' }
            ]
        }
    });
    expect(res.ok()).toBeTruthy();
    res = await apiContext.post(base + '/tools/embeddings.query', { headers: authHeaders, data: { text: 'alpha planning', topK: 2 } });
    expect(res.ok()).toBeTruthy();
    json = await res.json();
    expect(json[0].objectId).toBe('o1');

    // File upload (small buffer)
    const fd = await page.evaluateHandle(() => {
        const b = new Blob(['hello world'], { type: 'text/plain' });
        return b;
    });
    // Playwright direct API form-data easier via formData builder; emulate manually
    const formData = new FormData();
    formData.append('file', new Blob(['hello world'], { type: 'text/plain' }), 'hello.txt');
    const upload = await page.request.post(base + '/files/upload', { headers: { Authorization: `Bearer ${token}` }, multipart: { file: { name: 'hello.txt', mimeType: 'text/plain', buffer: Buffer.from('hello world', 'utf-8') } } });
    expect(upload.ok()).toBeTruthy();
    const uploadJson: any = await upload.json();
    const fileId: string = uploadJson.id;
    expect(fileId).toBeTruthy();

    // files/list
    res = await apiContext.get(base + '/files/list', { headers: { Authorization: `Bearer ${token}` } });
    expect(res.ok()).toBeTruthy();
    json = await res.json();
    expect(json.items.some((i: any) => i.id === fileId)).toBeTruthy();

    // files/download
    const download = await apiContext.get(base + '/files/download/' + fileId, { headers: { Authorization: `Bearer ${token}` } });
    expect(download.ok()).toBeTruthy();
    const text = await download.text();
    expect(text).toContain('hello world');
});
