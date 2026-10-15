import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const require=createRequire(import.meta.url), moduleData=require('../native/module.json');
const hash=value=>createHash('sha256').update(value).digest('hex');
test('Native artifact matches package sources and a closed host import boundary',()=>{
  const source=['../as/protocol.ts','../as/base.ts'].map(path=>readFileSync(new URL(path,import.meta.url),'utf8')).join('\0');
  assert.equal(hash(source),moduleData.sourceSha256);
  const wasm=Buffer.from(moduleData.wasm,'base64');assert.equal(hash(wasm),moduleData.sha256);
  assert.equal(moduleData.abi,'pulse.package-wasm.v1');
  const compiled=new WebAssembly.Module(wasm);
  assert.deepEqual(WebAssembly.Module.imports(compiled).map(({module,name})=>module+'.'+name).sort(),['env.abort','pulse_package.input_len','pulse_package.input_read']);
});
test('Pulse profile requires an explicit bounded policy and rejects unknown switches',()=>{
  const {invocation}=require('../pulse-profile.cjs');
  const profile={id:'test',label:'sig1',authority:'example.test',tag:'test',trustDomain:'test',maxAgeSeconds:60,clockSkewSeconds:5};
  assert.equal(invocation('verify',{binding:'test',profile}).artifact,'pulse.http-signatures:test');
  for(const changed of [{...profile,replay:'required'},{...profile,algorithm:'rsa-v1_5-sha256'},{...profile,maxAgeSeconds:0},{...profile,clockSkewSeconds:301},{...profile,authority:'other.test\nspoof'}, {...profile,tag:'bad\nfield'}]) assert.throws(()=>invocation('verify',{binding:'test',profile:changed}));
  assert.throws(()=>invocation('verify',{binding:'test',profile,request:{}}));
  assert.throws(()=>invocation('other',{binding:'test',profile}));
});
