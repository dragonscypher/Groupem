import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { defineConfig, type PluginOption } from 'vite';

export default defineConfig({
    plugins: [react()] as PluginOption[],
    build: {
        outDir: 'dist',
        emptyOutDir: true,
        sourcemap: false,
        minify: false,
        rollupOptions: {
            output: {
                manualChunks: undefined,
                entryFileNames: `[name].js`,
                assetFileNames: `[name].[ext]`
            },
            input: {
                popup: resolve(__dirname, 'src/popup.html'),
                options: resolve(__dirname, 'src/options.html'),
                background: resolve(__dirname, 'src/background.ts'),
                activator: resolve(__dirname, 'src/activator.ts')
            }
        }
    }
});
