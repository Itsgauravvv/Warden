/**
 * Threat-modeling Warden itself: prevent SSRF through custom provider base URLs.
 * Blocks HTTP (requires HTTPS), localhost, loopback, link-local (169.254.x.x),
 * and RFC1918 private IP ranges.
 */
export function validateSafeUpstreamUrl(rawUrl: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("Invalid upstream base URL");
  }

  if (parsed.protocol !== "https:") {
    throw new Error("Upstream base URL must use HTTPS");
  }

  const host = parsed.hostname.toLowerCase();

  if (
    host === "localhost" ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host === "[::1]" ||
    host.startsWith("[fe80:") ||
    host.startsWith("[fc") ||
    host.startsWith("[fd")
  ) {
    throw new Error("SSRF blocked: private or loopback hostname not allowed");
  }

  // Check IPv4 literals
  const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (ipv4Match) {
    const octets = ipv4Match.slice(1, 5).map(Number);
    const [a, b] = octets;
    if (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) || // Cloud metadata service
      (a === 172 && b !== undefined && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b !== undefined && b >= 64 && b <= 127)
    ) {
      throw new Error("SSRF blocked: private IPv4 range not allowed");
    }
  }

  return parsed;
}