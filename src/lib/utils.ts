/**
 * Safely parses the SBC IP input, stripping protocols if present, 
 * validating the format, and returning formatted WebSocket and HTTP URLs.
 * Returns null if the URL cannot be parsed.
 */
export function parseSbcAddress(input: string): { host: string; port: string; wsUrl: string; httpUrl: string } | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  // Add a protocol prefix if one isn't present, so URL constructor can process it.
  let urlString = trimmed;
  if (!/^(ws|wss|http|https):\/\//i.test(urlString)) {
    urlString = 'http://' + urlString;
  }

  try {
    // If the input has spaces or illegal characters, URL constructor will throw
    const parsed = new URL(urlString);
    
    // Extracted hostname (e.g. "localhost" or "192.168.1.100" or "[::1]")
    const hostname = parsed.hostname;
    if (!hostname) return null;

    // Use parsed port or fall back to "8085"
    const port = parsed.port || "8085";

    // Format for IPv6 if hostname contains colons and is not enclosed in brackets
    let hostStr = hostname;
    if (hostname.includes(':') && !hostname.startsWith('[') && !hostname.endsWith(']')) {
      hostStr = `[${hostname}]`;
    }

    const wsUrl = `ws://${hostStr}:${port}/events`;
    const httpUrl = `http://${hostStr}:${port}`;

    return {
      host: hostStr,
      port,
      wsUrl,
      httpUrl
    };
  } catch (e) {
    return null;
  }
}
