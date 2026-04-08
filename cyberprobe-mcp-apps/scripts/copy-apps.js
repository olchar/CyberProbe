/**
 * Copy MCP App manifests to dist folder
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const srcApps = path.join(__dirname, '../src/apps');
const distApps = path.join(__dirname, '../dist/apps');

// Create dist/apps directory
if (!fs.existsSync(distApps)) {
  fs.mkdirSync(distApps, { recursive: true });
}

// Copy app files
const files = fs.readdirSync(srcApps);
files.forEach(file => {
  const srcFile = path.join(srcApps, file);
  const distFile = path.join(distApps, file);
  fs.copyFileSync(srcFile, distFile);
  console.log(`Copied ${file} to dist/apps/`);
});

console.log('MCP App manifests copied successfully');
