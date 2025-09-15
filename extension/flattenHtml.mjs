import { promises as fs } from 'fs';
import { resolve } from 'path';

async function run() {
    const dist = resolve('./dist/src');
    const root = resolve('./dist');
    for (const name of ['popup.html', 'options.html']) {
        const from = resolve(dist, name);
        try {
            await fs.access(from);
            const to = resolve(root, name);
            await fs.copyFile(from, to);
            console.log('Copied', from, '->', to);
        } catch {
            // ignore if not exists
        }
    }
}
run();
