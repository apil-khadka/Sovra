// Live JSON hint for operator inputs (correction fields, JWK
// pastes). Empty is neutral — no error until the operator types
// something that does not parse.

/** Null when empty or parseable, else a short human reason. */
export function jsonError(value: string): string | null {
  if (value.trim() === '') return null
  try {
    JSON.parse(value)
    return null
  } catch {
    return 'Must be valid JSON.'
  }
}

/** Submit stays disabled while the input is blank or unparseable. */
export function jsonBlocked(value: string): boolean {
  return value.trim() === '' || jsonError(value) !== null
}
