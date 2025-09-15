import { spawn } from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as path from 'path';

async function waitForPort(port: number, host = '127.0.0.1', timeoutMs = 15000) {
    const start = Date.now();
    return new Promise<void>((resolve, reject) => {
        const attempt = () => {
            const socket = net.createConnection({ port, host }, () => {
                socket.end();
                resolve();
            });
            socket.on('error', () => {
                socket.destroy();
                if (Date.now() - start > timeoutMs) return reject(new Error('timeout waiting for port ' + port));
                setTimeout(attempt, 300);
            });
        };
        attempt();
    });
}

let serverProc: ReturnType<typeof spawn> | null = null;

async function buildServer(root: string) {
    await new Promise<void>((resolve, reject) => {
        if (process.platform === 'win32') {
            const p = spawn('cmd.exe', ['/c', 'npm', '-w', 'mcp-server', 'run', 'build'], { cwd: root, stdio: 'inherit' });
            p.on('close', code => code === 0 ? resolve() : reject(new Error('build failed')));
        } else {
            const p = spawn('npm', ['-w', 'mcp-server', 'run', 'build'], { cwd: root, stdio: 'inherit' });
            p.on('close', code => code === 0 ? resolve() : reject(new Error('build failed')));
        }
    });
}

async function buildExtension(root: string) {
    // Run vite build in extension workspace
    await new Promise<void>((resolve, reject) => {
        let command: string; let args: string[];
        if (process.platform === 'win32') {
            command = 'cmd.exe'; args = ['/c', 'npm', '-w', 'extension', 'run', 'build'];
        } else {
            command = 'npm'; args = ['-w', 'extension', 'run', 'build'];
        }
        const proc = spawn(command, args, { cwd: root, stdio: 'inherit' });
        proc.on('close', (code: number | null) => code === 0 ? resolve() : reject(new Error('extension build failed')));
    });
    // Copy manifest.json (kept in src) into dist if missing
    const manifestSrc = fs.existsSync(path.join(root, 'extension', 'src', 'manifest.json')) ? path.join(root, 'extension', 'src', 'manifest.json') : null;
    const manifestDst = path.join(root, 'extension', 'dist', 'manifest.json');
    if (manifestSrc && !fs.existsSync(manifestDst)) {
        fs.copyFileSync(manifestSrc, manifestDst);
    }
}

export default async function globalSetup() {
    const root = path.resolve(__dirname, '..', '..');
    await buildExtension(root);
    await buildServer(root);
    // Start server from built dist to avoid ts-node overhead
    const serverEntry = path.join(root, 'mcp-server', 'dist', 'index.js');
    serverProc = spawn(process.execPath, [serverEntry], { cwd: root, stdio: 'inherit' });
    try {
        await waitForPort(8080, '127.0.0.1');
    } catch (e) {
        console.error('Server failed to start in time', e);
        serverProc?.kill();
        throw e;
    }
    // Expose teardown
    return async () => {
        if (serverProc && !serverProc.killed) serverProc.kill();
    };
}
