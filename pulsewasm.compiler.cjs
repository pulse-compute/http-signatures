'use strict';
const moduleData = require('./native/module.json');
const { invocation } = require('./pulse-profile.cjs');
const name = '@pulse-compute/http-signatures', contractId = 'pulse.http-signatures', subpath = name + '/pulse';
function build(input) {
  const ts = input.typescript, source = input.sourceFile, effects = [], diagnostics = [], artifacts = [];
  const aliases = new Map(), namespaces = new Set();
  function error(node, code) {
    const p = source.getLineAndCharacterOfPosition(node.getStart(source));
    diagnostics.push({ code, severity: 'error', message: 'Native HTTP Signatures requires an awaited call with the current context and literal binding/profile options.',
      loc: { file: source.fileName, line: p.line + 1, column: p.character + 1 } });
  }
  function literal(node) {
    if (ts.isStringLiteral(node)) return node.text;
    if (ts.isNumericLiteral(node)) return Number(node.text);
    if (ts.isObjectLiteralExpression(node)) {
      const out = Object.create(null);
      for (const p of node.properties) {
        if (!ts.isPropertyAssignment(p) || !(ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) || Object.hasOwn(out, p.name.text)) throw Error();
        out[p.name.text] = literal(p.initializer);
      }
      return out;
    }
    throw Error();
  }
  for (const node of source.statements) if (ts.isImportDeclaration(node) && node.moduleSpecifier.text === subpath) {
    const bindings = node.importClause?.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) namespaces.add(bindings.name.text);
    else if (bindings) for (const e of bindings.elements) {
      const symbol = e.propertyName?.text || e.name.text;
      if (symbol === 'signatures') namespaces.add(e.name.text); else aliases.set(e.name.text, symbol);
    }
  }
  const shadowed = new Set();
  function declarations(node) {
    if ((ts.isVariableDeclaration(node) || ts.isParameter(node) || ts.isBindingElement(node)
      || ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) && node.name && ts.isIdentifier(node.name)
      && (aliases.has(node.name.text) || namespaces.has(node.name.text))) shadowed.add(node.name.text);
    ts.forEachChild(node, declarations);
  }
  declarations(source);
  function visit(node) {
    if (ts.isCallExpression(node)) {
      const target = node.expression;
      const operation = ts.isIdentifier(target) ? aliases.get(target.text)
        : ts.isPropertyAccessExpression(target) && ts.isIdentifier(target.expression) && namespaces.has(target.expression.text) ? target.name.text : null;
      if (operation) {
        const importedName = ts.isIdentifier(target) ? target.text : target.expression.text;
        if (shadowed.has(importedName)) { error(node, 'HMS_NATIVE_IMPORT_SHADOWED'); return; }
        let enclosing = node.parent;
        while (enclosing && !ts.isArrowFunction(enclosing) && !ts.isFunctionExpression(enclosing) && !ts.isFunctionDeclaration(enclosing)) enclosing = enclosing.parent;
        if (node.arguments.length !== 2 || !ts.isIdentifier(node.arguments[0])
          || enclosing?.parameters[0]?.name?.text !== node.arguments[0].text) { error(node, 'HMS_NATIVE_CONTEXT_REQUIRED'); return; }
        if (!ts.isAwaitExpression(node.parent) || !ts.isVariableDeclaration(node.parent.parent)) { error(node, 'HMS_NATIVE_AWAIT_REQUIRED'); return; }
        let payload;
        try { payload = invocation(operation, literal(node.arguments[1])); }
        catch { error(node, 'HMS_NATIVE_OPTIONS_STATIC'); return; }
        const p = source.getLineAndCharacterOfPosition(node.getStart(source));
        effects.push({ version: 'pulse.canonical-package-effect.v1', package: name, contractId, import: subpath,
          kind: 'package.invoke', providerKind: 'package', operation: 'invoke', capability: 'package.invoke', result: 'string',
          placement: 'variable', resource: { kind: 'none' }, payload, runtimeInputs: [], providerRequirements: ['package.invoke'],
          schemaReferences: [], redaction: ['input', 'output', 'headers', 'body', 'key-material'],
          range: { start: node.getStart(source), end: node.getEnd() }, loc: { file: source.fileName, line: p.line + 1, column: p.character + 1 } });
        const artifact = { version: 'pulse.package-runtime-binding.v1', id: payload.artifact, contractId, package: name,
          kind: 'package-runtime-wasm', mediaType: 'application/wasm', data: { abi: moduleData.abi, wasm: moduleData.wasm, sha256: moduleData.sha256,
            operations: ['sign', 'verify'].map(name => ({ name, configuration: payload.configuration,
              capabilities: ['http.snapshot', 'time.wall-clock', 'crypto.sha256', 'crypto.hmac-sha256'] })) } };
        const prior = artifacts.find(a => a.id === artifact.id);
        if (prior && JSON.stringify(prior) !== JSON.stringify(artifact)) error(node, 'HMS_NATIVE_PROFILE_COLLISION');
        else if (!prior) artifacts.push(artifact);
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  return { artifact: { version: 'pulse.http-signatures-lowering.v1', contractId, package: name, lowerableSubpath: subpath,
    status: diagnostics.length ? 'error' : 'ok' }, canonicalEffects: effects, realizationArtifacts: artifacts,
    cryptoRequirements: effects.length ? [{ version: 'pulse.package-crypto-requirement.v1', requestedBy: name,
      semanticOwner: '@pulse-compute/crypto', reachable: true, algorithms: ['SHA-256', 'HMAC-SHA256'] }] : [], diagnostics, hasErrors: diagnostics.length > 0 };
}
module.exports = { build };
