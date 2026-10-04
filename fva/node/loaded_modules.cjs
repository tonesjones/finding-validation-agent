'use strict';
// FVA loaded-module recorder (passive; sends no traffic).
// Use: FVA_LOADED_MODULES_DIR=<dir> NODE_OPTIONS="--require <this file>" npm test
// Records file paths only: no request data, arguments, environment values or memory contents.
// Each path is appended as it loads, so a process killed by a signal still leaves its record.
const fs = require('fs');
const path = require('path');
const { fileURLToPath } = require('url');
const Module = require('module');

const dir = process.env.FVA_LOADED_MODULES_DIR;
if (dir) {
  fs.mkdirSync(dir, { recursive: true });
  const out = path.join(dir, `loaded-${process.pid}-${Date.now()}.jsonl`);
  // Without load hooks, ESM imports are invisible, so the importer will not trust absences.
  const hooks = typeof Module.registerHooks === 'function';
  fs.writeFileSync(out, JSON.stringify({ format: 'fva.loaded_modules/1', node: process.version, hooks }) + '\n');
  const seen = new Set();
  const record = (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    fs.appendFileSync(out, JSON.stringify(file) + '\n');
  };
  if (hooks) {
    Module.registerHooks({
      load(url, context, nextLoad) {
        if (url.startsWith('file:')) record(fileURLToPath(url));
        return nextLoad(url, context);
      },
    });
  }
  process.on('exit', () => {
    for (const file of Object.keys(require.cache)) record(file);
  });
}
