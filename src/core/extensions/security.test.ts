import { describe, expect, test } from 'bun:test';
import { API_VERSION } from '@pixprite/api';
import { parseManifest, validateManifest } from './manifest';
import { resolvePath, safePath } from './paths';
import { METHODS, missingPermission, PERMISSION_FOR_METHOD } from './protocol';
import { isNetworkAllowed, parseNetworkPermission, parseNetworkUrl } from './network';

const manifest = () => ({ id: 'security-test', name: 'Security', version: '1.0.0', apiVersion: API_VERSION });

describe('extension capability boundary', () => {
  test('every protected method rejects a missing capability', () => {
    for (const method of METHODS) {
      const permission = PERMISSION_FOR_METHOD[method];
      expect(missingPermission(method, [], 'https://example.test/file')).toBe(permission === 'network' ? 'network:example.test' : permission);
      if (permission && permission !== 'network') expect(missingPermission(method, [permission])).toBeNull();
    }
    expect(missingPermission('__proto__', [])).toBe('__proto__');
    expect(missingPermission('constructor', [])).toBe('constructor');
  });
  test('network hosts match exactly, including ports; URL credentials and suffixes give no extra access', () => {
    const permissions = ['network:allowed.test', 'network:localhost:4173'];
    for (const url of ['https://allowed.test/', 'https://allowed.test:443/a', 'http://localhost:4173']) expect(missingPermission('net.fetch', permissions, url)).toBeNull();
    for (const url of ['https://allowed.test.evil.test', 'https://allowed.test@evil.test', 'https://allowed.test:444', 'http://localhost:4174', 'invalid']) expect(missingPermission('net.fetch', permissions, url)).not.toBeNull();
    expect(missingPermission('net.fetch', ['network:*'], 'https://other.test')).toBeNull();
  });
});

describe('network permission port normalization and string parsing', () => {
  test('an explicit scheme-default port in the permission matches a URL that omits the port', () => {
    expect(isNetworkAllowed(['network:allowed.test:443'], 'https://allowed.test/')).toBe(true);
    expect(isNetworkAllowed(['network:allowed.test:443'], 'https://allowed.test:443/path')).toBe(true);
    expect(isNetworkAllowed(['network:allowed.test:80'], 'http://allowed.test/')).toBe(true);
    // Default ports are per scheme: 443 in the permission does not cover an http (port 80) URL.
    expect(isNetworkAllowed(['network:allowed.test:443'], 'http://allowed.test/')).toBe(false);
    expect(isNetworkAllowed(['network:allowed.test:80'], 'https://allowed.test/')).toBe(false);
    expect(missingPermission('net.fetch', ['network:allowed.test:443'], 'https://allowed.test/')).toBeNull();
  });
  test('a non-default port in the permission never matches a URL that falls back to the default port', () => {
    expect(isNetworkAllowed(['network:api.test:8080'], 'http://api.test/')).toBe(false);
    expect(isNetworkAllowed(['network:api.test:8080'], 'https://api.test/')).toBe(false);
    // It still matches when the URL names that exact port.
    expect(isNetworkAllowed(['network:api.test:8080'], 'http://api.test:8080/')).toBe(true);
    // And a port-less permission (default origin) does not cover a URL on a non-default port.
    expect(isNetworkAllowed(['network:api.test'], 'https://api.test:8080/')).toBe(false);
    expect(missingPermission('net.fetch', ['network:api.test:8080'], 'https://api.test/')).not.toBeNull();
  });
  test('illegal permission strings parse to null and never grant access', () => {
    for (const permission of ['network:', 'network::443', 'network:host::443', 'network:host:443:80', 'network::', 'network: :443', 'network:host:0', 'network:host:99999', 'network:host:abc', 'storage', '']) {
      expect(parseNetworkPermission(permission), permission).toBeNull();
      expect(isNetworkAllowed([permission], 'https://host/'), permission).toBe(false);
    }
    // A malformed entry must not shadow a valid sibling permission.
    expect(isNetworkAllowed(['network:', 'network:allowed.test'], 'https://allowed.test/')).toBe(true);
    expect(parseNetworkPermission('network:ALLOWED.TEST:443')).toEqual({ host: 'allowed.test', port: 443 });
    expect(parseNetworkPermission('network:*')).toEqual({ host: '*', port: null });
  });
  test('URL parsing normalizes default ports and rejects credentials and non-http(s) schemes', () => {
    expect(parseNetworkUrl('https://allowed.test/')).toEqual({ host: 'allowed.test', port: 443, defaultPort: 443 });
    expect(parseNetworkUrl('http://allowed.test:80/')).toEqual({ host: 'allowed.test', port: 80, defaultPort: 80 });
    expect(parseNetworkUrl('https://allowed.test:443/')?.port).toBe(443);
    expect(parseNetworkUrl('https://user:pass@allowed.test/')).toBeNull();
    expect(parseNetworkUrl('ftp://allowed.test/')).toBeNull();
    expect(parseNetworkUrl('not a url')).toBeNull();
  });
});

describe('untrusted package paths and manifests', () => {
  const attacks = ['../main.js', 'a/../../main.js', '/main.js', '//evil.test/main.js', 'https://evil.test/a', 'a\\..\\main.js', '%2e%2e/main.js', 'a/%252e%252e/main.js', 'a?x.js', 'a#x.js', 'a\n.js', 'a/./main.js'];
  test('all package path fields reject traversal and URL rewriting', () => {
    for (const path of attacks) {
      expect(safePath(path)).toBe(false);
      const fields = [
        { entry: path }, { icon: path },
        { contributes: { tools: [{ id: 'a', label: 'a', group: 'a', icon: path }] }, entry: 'main.js' },
        { permissions: ['ui:panel'], contributes: { panels: [{ id: 'a', label: 'a', dock: 'left', page: path }] } },
        { permissions: ['ui:panel'], contributes: { widgets: [{ id: 'a', slot: 'toolbar', page: path }] } },
        { contributes: { locales: path } },
        { contributes: { iconPacks: [{ id: 'icons', label: 'Icons', icons: path }] } },
        { contributes: { languages: [{ code: 'en', name: 'English', dir: 'ltr', dict: path }] } },
        { contributes: { languages: [{ code: 'en', name: 'English', dir: 'ltr', dict: 'en.json', extensions: { a: path } }] } },
      ];
      for (const field of fields) expect(validateManifest({ ...manifest(), ...field }).some(e => e.includes('relative path'))).toBe(true);
    }
    expect(safePath('src/main.ts')).toBe(true);
    expect(safePath('locales/')).toBe(true);
  });
  test('relative import normalization permits internal parents but refuses escapes and encoded separators', () => {
    expect(resolvePath('src/../main.ts')).toBe('main.ts');
    for (const p of ['../secret.ts', 'src/../../secret.ts', 'src/..\\secret.ts', 'src/%2e%2e/secret.ts', '/secret.ts']) expect(resolvePath(p)).toBeNull();
  });
  test('malformed manifests reject before they can become installed code', () => {
    for (const value of [null, [], {}, { ...manifest(), apiVersion: 99 }, { ...manifest(), permissions: 'storage' }, { ...manifest(), permissions: ['unknown'] }, { ...manifest(), contributes: [] }, { ...manifest(), contributes: { panels: [null] } }, { ...manifest(), contributes: { commands: [{ id: 'x', label: 'x' }] } }]) expect(() => parseManifest(value)).toThrow('Invalid manifest');
    expect(parseManifest(manifest()).id).toBe('security-test');
  });
});
