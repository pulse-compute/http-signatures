import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('README Usage snippets execute with the documented HMAC host setup', () => {
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const snippet = name => {
    const match = readme.match(new RegExp('<!-- usage:' + name + ' -->\\s*```js\\n([\\s\\S]*?)\\n```'));
    assert.ok(match, 'Missing README snippet: ' + name);
    return match[1];
  };
  const source = `
    import assert from 'node:assert/strict';
    import { message, profile, parameters, signer, clock, receivingProfile, keys, receive }
      from './examples/hmac-context.mjs';
    ${snippet('sign')}
    const received = receive(signatureHeaders);
    ${snippet('verify')}
    assert.equal(checked.value.profileId, profile.id);
    assert.equal(checked.value.keyId, 'example-key');
    assert.equal(checked.value.bodyIntegrity, 'not-checked');
    assert.equal(checked.value.replay, 'not-checked');
    received.method.value = 'POST';
    assert.deepEqual(await verify(received, {
      profile: receivingProfile, capabilities: { keys, clock },
    }), { ok: false, code: 'SIGNATURE_INVALID' });
  `;
  const run = spawnSync(process.execPath, ['--input-type=module', '--eval', source], {
    cwd: fileURLToPath(new URL('..', import.meta.url)), encoding: 'utf8', timeout: 10000,
  });
  assert.ifError(run.error);
  assert.equal(run.status, 0, run.stderr);
});
