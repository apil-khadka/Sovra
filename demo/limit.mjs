// Zero-dependency per-key token bucket (PROD-006). Shared by the
// demo RP servers for coarse per-IP abuse protection: the showcase
// server and the copy-paste template enforce the same shape, so
// integrators inherit the control with the template.
//
// Pure and clock-injectable for deterministic smoke assertions.

export function createRateLimiter({ capacity, refillPerSec, now = () => Date.now() }) {
  const buckets = new Map()
  return {
    allow(key) {
      const at = now() / 1000
      let bucket = buckets.get(key)
      if (bucket === undefined) {
        bucket = { tokens: capacity, at }
        buckets.set(key, bucket)
      } else {
        bucket.tokens = Math.min(capacity, bucket.tokens + refillPerSec * (at - bucket.at))
        bucket.at = at
      }
      if (bucket.tokens < 1) {
        const retryAfterSec = Math.max(1, Math.ceil((1 - bucket.tokens) / refillPerSec))
        return { allowed: false, retryAfterSec }
      }
      bucket.tokens -= 1
      return { allowed: true, retryAfterSec: 0 }
    },
  }
}

// Same-origin policy for demo APIs (PROD-006). Browsers send Origin
// on POST; non-browser clients send none. Missing Origin is allowed
// (curl, smoke, server-to-server); a present but foreign Origin is
// rejected. Localhost of any port is the demo's whole world.
export function originAllowed(origin) {
  if (origin === undefined || origin === null || origin === '') return true
  let host = ''
  try {
    host = new URL(origin).hostname
  } catch {
    return false
  }
  return host === 'localhost' || host === '127.0.0.1'
}
