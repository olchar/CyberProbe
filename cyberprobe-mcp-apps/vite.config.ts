import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';
import path from 'path';

const input = process.env.INPUT || 'mcp-app.html';

export default defineConfig({
  plugins: [viteSingleFile()],
  build: {
    target: 'esnext',
    outDir: 'dist',
    emptyOutDir: false,
    copyPublicDir: false,
    rollupOptions: {
      input: path.resolve(__dirname, input),
      output: {
        entryFileNames: '[name].js',
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
});
