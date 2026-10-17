'use strict';
const fields = ['id', 'label', 'authority', 'tag', 'trustDomain', 'maxAgeSeconds', 'clockSkewSeconds'];
function data(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || Reflect.ownKeys(value).some(key => typeof key !== 'string' || !keys.includes(key)
      || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'))) throw new TypeError('HMS_NATIVE_OPTIONS_INVALID');
}
function configuration(profile) {
  data(profile, fields);
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)
    || Object.keys(profile).length !== fields.length || Object.keys(profile).some(key => !fields.includes(key))) throw new TypeError('HMS_NATIVE_PROFILE_INVALID');
  for (const key of fields.slice(0, 5)) {
    if (typeof profile[key] !== 'string' || !profile[key].length || profile[key].length > 512 || /[^\x20-\x7e]/.test(profile[key])) throw new TypeError('HMS_NATIVE_PROFILE_INVALID');
  }
  if (!/^[a-zA-Z0-9._-]{1,128}$/.test(profile.id) || !/^[a-z*][a-z0-9_.*-]{0,63}$/.test(profile.label)
    || !/^[a-z0-9.-]+(?::[0-9]{1,5})?$/.test(profile.authority)
    || !Number.isSafeInteger(profile.maxAgeSeconds) || profile.maxAgeSeconds < 1 || profile.maxAgeSeconds > 3600
    || !Number.isSafeInteger(profile.clockSkewSeconds) || profile.clockSkewSeconds < 0 || profile.clockSkewSeconds > 300) throw new TypeError('HMS_NATIVE_PROFILE_INVALID');
  return fields.map(key => String(profile[key])).join('\n');
}
function invocation(operation, options) {
  data(options, ['binding', 'profile']);
  if (!['sign', 'verify'].includes(operation) || !options || Object.keys(options).length !== 2
    || !Object.hasOwn(options, 'profile') || typeof options.binding !== 'string' || !/^[a-zA-Z0-9._-]{1,128}$/.test(options.binding)) throw new TypeError('HMS_NATIVE_OPTIONS_INVALID');
  const config = configuration(options.profile);
  return { artifact: 'pulse.http-signatures:' + options.profile.id, binding: options.binding, operation, configuration: config };
}
module.exports = Object.freeze({ configuration, invocation });
