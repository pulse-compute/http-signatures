import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
for (const directory of ['src', 'test', 'scripts']) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isFile() || !/\.m?js$/.test(entry.name)) continue;
    const result = spawnSync(process.execPath, ['--check', `${directory}/${entry.name}`], { stdio: 'inherit' });
    if (result.error || result.status !== 0) process.exit(result.status || 1);
  }
}
