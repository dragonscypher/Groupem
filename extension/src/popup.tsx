import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';

type TabInfo = { id: number; title: string; url: string; group?: string };
type Session = { id: string; createdAt: string; device: string; groups: Array<{ id: string; label: string; category: string; tabIds: string[] }> };

// Embeddings fallback: try ONNX local model, else ML service, else server TF-IDF
async function embedTexts(texts: string[]): Promise<number[][]> {
    // 1. ONNX runtime local attempt
    try {
        // Dynamically import to avoid cost if unused
        const ort: any = await import('onnxruntime-web');
        // Expect a small local model path packaged or skipped (placeholder: throw to next)
        if (ort && ort.InferenceSession) {
            // If you add a local model, load & infer here. For now, force fallback.
            throw new Error('no-local-model');
        }
    } catch { /* proceed */ }
    // 2. ML service
    try {
        const resp = await fetch('http://localhost:8000/embed', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: texts }) });
        if (resp.ok) {
            const data = await resp.json();
            if (Array.isArray(data.vectors)) return data.vectors;
        }
    } catch { /* swallow */ }
    // 3. Server-side TF-IDF fallback (index then query for each)
    try {
        const token = await getToken();
        if (token) {
            const objects = texts.map((t, i) => ({ id: 'loc-' + i, text: t }));
            await fetch('http://localhost:8080/tools/embeddings.index', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ objects }) });
            // Build crude one-hot style by querying similarity against each text individually
            const vectors: number[][] = [];
            for (const t of texts) {
                const r = await fetch('http://localhost:8080/tools/embeddings.query', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ text: t, topK: texts.length }) });
                if (r.ok) {
                    const scored = await r.json();
                    // Map scores into vector aligned with objects order
                    const map: Record<string, number> = {};
                    for (const s of scored) map[s.objectId] = s.score;
                    vectors.push(objects.map(o => map[o.id] || 0));
                } else {
                    vectors.push(new Array(texts.length).fill(0));
                }
            }
            return vectors;
        }
    } catch { /* ignore */ }
    return texts.map(() => []);
}

async function fetchTabs(): Promise<TabInfo[]> {
    const tabs: Array<{ id?: number; title?: string; url?: string }> = await browser.tabs.query({ currentWindow: true });
    return tabs.map(t => ({ id: t.id || 0, title: t.title || '', url: t.url || '' }));
}

function clusterTabs(tabs: TabInfo[]): TabInfo[] {
    const map = new Map<string, string>();
    for (const tab of tabs) {
        try {
            const u = new URL(tab.url);
            map.set(tab.url, u.hostname.split('.').slice(-2).join('.'));
        } catch { map.set(tab.url, 'other'); }
    }
    return tabs.map(t => ({ ...t, group: map.get(t.url) }));
}

async function getToken(): Promise<string | null> {
    const stored = await browser.storage.local.get('token');
    const value = (stored as any).token;
    return typeof value === 'string' ? value : null;
}

async function listSessions(): Promise<Session[]> {
    const token = await getToken();
    if (!token) return [];
    const res = await fetch('http://localhost:8080/tools/tabs.listGroups', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: '{}' });
    if (!res.ok) return [];
    const data = await res.json();
    return data.items || [];
}

async function saveSession(tabs: TabInfo[]): Promise<string | null> {
    const token = await getToken();
    if (!token) return null;
    const groupsMap: Record<string, string[]> = {};
    for (const t of tabs) {
        const g = t.group || 'ungrouped';
        groupsMap[g] = groupsMap[g] || [];
        groupsMap[g].push(String(t.id));
    }
    const groups = Object.entries(groupsMap).map(([label, tabIds]) => ({ id: label + Date.now(), label, category: label, tabIds }));
    const body = { session: { id: crypto.randomUUID(), createdAt: new Date().toISOString(), device: 'extension', groups } };
    const res = await fetch('http://localhost:8080/tools/tabs.saveGroups', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
    if (res.ok) { const d = await res.json(); return d.id; }
    return null;
}

async function loadSession(id: string): Promise<Session | null> {
    const token = await getToken();
    if (!token) return null;
    const res = await fetch('http://localhost:8080/tools/tabs.loadGroups', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ id }) });
    if (!res.ok) return null;
    return await res.json();
}

const App: React.FC = () => {
    const [tabs, setTabs] = useState<TabInfo[]>([]);
    const [sessions, setSessions] = useState<Session[]>([]);
    const [saving, setSaving] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [embeddingStatus, setEmbeddingStatus] = useState<string>('');
    const [token, setToken] = useState<string | null>(null);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [totp, setTotp] = useState('');
    const [authError, setAuthError] = useState<string | null>(null);
    const [registerMode, setRegisterMode] = useState(false);
    const [phone, setPhone] = useState('');
    const [provisionedSecret, setProvisionedSecret] = useState<string | null>(null);

    useEffect(() => {
        (async () => {
            try {
                const stored = await browser.storage.local.get(['token', 'userEmail']);
                const existing = (stored as any).token || null;
                const storedEmail = (stored as any).userEmail || '';
                setToken(existing);
                if (storedEmail) setEmail(storedEmail);
                const t = await fetchTabs();
                setTabs(clusterTabs(t));
                if (existing) setSessions(await listSessions());
            } catch (e: any) {
                setError('Failed to load tabs');
            } finally { setLoading(false); }
        })();
    }, []);

    async function handleSave() {
        setSaving(true);
        const id = await saveSession(tabs);
        setSaving(false);
        if (id) setSessions(await listSessions());
    }

    async function handleRestore(id: string) {
        const session = await loadSession(id);
        if (session) {
            // For each group we just log; full tab recreation would need stored URLs
            console.log('Restored session', session.id, session.groups.length);
        }
    }

    async function handleEmbeddingsTest() {
        setEmbeddingStatus('Embedding...');
        const texts = tabs.slice(0, 5).map(t => t.title || t.url).filter(Boolean);
        const vectors = await embedTexts(texts);
        setEmbeddingStatus(`Generated ${vectors.length} vectors (len=${vectors[0]?.length || 0})`);
    }

    async function handleLogin(e: React.FormEvent) {
        e.preventDefault();
        setAuthError(null);
        try {
            const res = await fetch('http://localhost:8080/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, totp: totp || undefined }) });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                setAuthError(data.error || 'login-failed');
                return;
            }
            const data = await res.json();
            await browser.storage.local.set({ token: data.token, userEmail: email });
            setToken(data.token);
            setSessions(await listSessions());
        } catch {
            setAuthError('network');
        }
    }

    async function handleRegister(e: React.FormEvent) {
        e.preventDefault();
        setAuthError(null);
        setProvisionedSecret(null);
        try {
            const body: any = { email, password };
            if (phone) body.phone = phone;
            body.autoTotp = true; // auto enroll if register mode
            const res = await fetch('http://localhost:8080/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setAuthError(data.error || 'register-failed');
                return;
            }
            if (data.totpSecret) setProvisionedSecret(data.totpSecret);
            // After registration, prompt user to login with newly provisioned TOTP
            setRegisterMode(false);
        } catch {
            setAuthError('network');
        }
    }

    async function handleLogout() {
        await browser.storage.local.remove('token');
        setToken(null);
        setSessions([]);
    }

    if (loading) return <div style={{ fontFamily: 'sans-serif', width: 360 }}>Loading...</div>;
    if (error) return <div style={{ fontFamily: 'sans-serif', width: 360, color: 'red' }}>{error}</div>;

    if (!token) {
        return <div style={{ fontFamily: 'sans-serif', width: 360 }}>
            <h3>{registerMode ? 'Register' : 'Groupem Login'}</h3>
            <form onSubmit={registerMode ? handleRegister : handleLogin}>
                <div style={{ marginBottom: 6 }}>
                    <input style={{ width: '100%' }} placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
                </div>
                <div style={{ marginBottom: 6 }}>
                    <input style={{ width: '100%' }} placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
                </div>
                {registerMode && <div style={{ marginBottom: 6 }}>
                    <input style={{ width: '100%' }} placeholder="Phone (optional)" value={phone} onChange={e => setPhone(e.target.value)} />
                </div>}
                {!registerMode && <div style={{ marginBottom: 6 }}>
                    <input style={{ width: '100%' }} placeholder="TOTP (if enrolled)" value={totp} onChange={e => setTotp(e.target.value)} />
                </div>}
                <button type="submit" disabled={!email || !password}>{registerMode ? 'Register' : 'Login'}</button>
                <button type="button" style={{ marginLeft: 8 }} onClick={() => { setRegisterMode(!registerMode); setAuthError(null); }}>{registerMode ? 'Have account?' : 'Create account'}</button>
                {authError && <div style={{ color: 'red', fontSize: 12, marginTop: 4 }}>{authError}</div>}
                {provisionedSecret && <div style={{ fontSize: 11, marginTop: 6 }}>TOTP Secret: <code>{provisionedSecret}</code></div>}
            </form>
        </div>;
    }

    const groupLabels = Array.from(new Set(tabs.map(t => t.group || 'other')));

    return <div style={{ fontFamily: 'sans-serif', width: 360 }}>
        <h3>Groupem</h3>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 12, opacity: 0.7 }}>{email || 'Logged in'}</span>
            <button onClick={handleLogout} style={{ fontSize: 11 }}>Logout</button>
        </div>
        <button onClick={handleSave} disabled={saving}>{saving ? 'Saving...' : 'Save Session'}</button>
        <button onClick={handleEmbeddingsTest} style={{ marginLeft: 8 }}>Test Embeddings</button>
        {embeddingStatus && <div style={{ fontSize: 11, marginTop: 4 }}>{embeddingStatus}</div>}
        <h4>Current Groups</h4>
        {groupLabels.length === 0 && <div>No tabs</div>}
        {groupLabels.map(g => <div key={g}><strong>{g}</strong><ul>{tabs.filter(t => (t.group || 'other') === g).map(t => <li key={t.id}>{t.title}</li>)}</ul></div>)}
        <h4>Saved Sessions</h4>
        <ul>{sessions.map(s => <li key={s.id}><button onClick={() => handleRestore(s.id)}>Restore</button> {new Date(s.createdAt).toLocaleTimeString()} ({s.groups.length} groups)</li>)}</ul>
    </div>;
};

createRoot(document.getElementById('root')!).render(<App />);
