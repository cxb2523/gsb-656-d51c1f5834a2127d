/**
 * Pure network permission matching for `net.fetch`, split out of `protocol.ts` so the rules
 * can be tested without any host/runtime state.
 *
 * A `network:<host>` or `network:<host>:<port>` permission grants exactly one origin:
 * the host must be identical (case-insensitive) and the effective port must be identical.
 * `network:*` grants every host. Everything else — credentials embedded in the URL,
 * suffix look-alikes, unknown schemes, malformed strings — is denied.
 */

const DEFAULT_PORTS: Readonly<Record<string, number>> = { 'http:': 80, 'https:': 443 };

export type NetworkPermission = {
  /** Lowercased host; '*' is only produced by the `network:*` wildcard */
  host: string;
  /** Explicitly declared port, or null when the permission declares no port */
  port: number | null;
};

export type NetworkTarget = {
  /** Lowercased host without userinfo (URLs carrying credentials never parse) */
  host: string;
  /** Effective port: the explicit URL port, or the scheme's default port */
  port: number;
  /** Default port of the URL scheme (80 for http, 443 for https) */
  defaultPort: number;
};

/**
 * Parses a `network:<host>[:<port>]` / `network:*` permission string.
 * Returns null for anything that is not a well-formed grant, including an empty host,
 * extra colons, non-numeric or out-of-range ports.
 */
export function parseNetworkPermission(permission: string): NetworkPermission | null {
  if (typeof permission !== 'string' || !permission.startsWith('network:')) return null;
  const rest = permission.slice('network:'.length);
  if (rest === '*') return { host: '*', port: null };

  const lastColon = rest.lastIndexOf(':');
  const hostPart = lastColon === -1 ? rest : rest.slice(0, lastColon);
  const portPart = lastColon === -1 ? null : rest.slice(lastColon + 1);
  if (!hostPart || hostPart.includes(':')) return null;
  // Manifests only allow [a-z0-9.-] hosts; reject anything else (empty labels, spaces, @, …)
  if (!/^[a-z0-9.-]+$/i.test(hostPart)) return null;

  let port: number | null = null;
  if (portPart !== null) {
    if (!/^\d+$/.test(portPart)) return null;
    const value = Number(portPart);
    if (!Number.isInteger(value) || value < 1 || value > 65535) return null;
    port = value;
  }
  return { host: hostPart.toLowerCase(), port };
}

/**
 * Parses a URL into the parts the network gate compares.
 * Only http/https URLs are fetchable and userinfo (`user:pass@host`) is always refused,
 * so such inputs return null rather than a target.
 */
export function parseNetworkUrl(url: string | undefined): NetworkTarget | null {
  let parsed: URL;
  try {
    parsed = new URL(url ?? '');
  } catch {
    return null;
  }
  const defaultPort = DEFAULT_PORTS[parsed.protocol];
  if (defaultPort === undefined) return null;
  // Credentials in the URL must never grant access to the host behind them
  if (parsed.username !== '' || parsed.password !== '') return null;
  const host = parsed.hostname.toLowerCase();
  if (!host) return null;
  return { host, port: parsed.port === '' ? defaultPort : Number(parsed.port), defaultPort };
}

/** The canonical label used in "permission X is not granted" errors */
export function describeNetworkTarget(target: NetworkTarget): string {
  return target.port === target.defaultPort ? `network:${target.host}` : `network:${target.host}:${target.port}`;
}

/** Whether one parsed permission covers one parsed URL target */
export function permissionCoversTarget(permission: NetworkPermission, target: NetworkTarget): boolean {
  if (permission.host === '*') return true;
  if (permission.host !== target.host) return false;
  // A port-less permission names the scheme-default origin; an explicit port must match exactly.
  const required = permission.port ?? target.defaultPort;
  return required === target.port;
}

/**
 * Whether any of the raw manifest permission strings grants `url`.
 * Malformed permission strings and unparseable URLs simply do not match.
 */
export function isNetworkAllowed(permissions: readonly string[], url: string | undefined): boolean {
  const target = parseNetworkUrl(url);
  if (!target) return false;
  return permissions.some(raw => {
    const permission = parseNetworkPermission(raw);
    return permission !== null && permissionCoversTarget(permission, target);
  });
}
