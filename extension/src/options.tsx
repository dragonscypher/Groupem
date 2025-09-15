import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';

const Options: React.FC = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [token, setToken] = useState<string | null>(null);

    async function login() {
        const res = await fetch('http://localhost:8080/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
        if (res.ok) {
            const data = await res.json();
            setToken(data.token);
        }
    }

    return <div style={{ fontFamily: 'sans-serif' }}>
        <h3>Groupem Login</h3>
        <input placeholder='Email' value={email} onChange={e => setEmail(e.target.value)} />
        <input placeholder='Password' type='password' value={password} onChange={e => setPassword(e.target.value)} />
        <button onClick={login}>Login</button>
        {token && <div>Logged in</div>}
    </div>;
};

createRoot(document.getElementById('root')!).render(<Options />);
