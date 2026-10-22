// ScanError and the error-code -> HTTP status map (SPEC Contract 3).
//
// Every failure that reaches the API is expressed as one of these codes. The
// `message` is plain English and safe to show to the visitor; nothing else
// about the underlying error (stack, errno, internal host names) ever leaves
// the server.

export const ERROR_STATUS = Object.freeze({
  invalid_url: 400,
  blocked_target: 400,
  rate_limited: 429,
  dns_failed: 422,
  unreachable: 502,
  timeout: 504,
  method_not_allowed: 405,
  forbidden: 403,
  internal: 500,
});

export const ERROR_MESSAGES = Object.freeze({
  invalid_url: "That doesn't look like a website address. Try something like example.com.",
  blocked_target: "That address points to a private or local network, so it can't be checked.",
  rate_limited: 'Too many checks in a short time. Wait a minute and try again.',
  dns_failed: "We couldn't find that domain. Check the spelling.",
  unreachable: "The site didn't respond. It may be down or blocking automated checks.",
  timeout: 'The site took too long to answer. Try again in a moment.',
  method_not_allowed: 'Use GET.',
  forbidden: 'Checks can only be started from the Surface website.',
  internal: 'Something went wrong on our side. Try again.',
});

export class ScanError extends Error {
  /**
   * @param {keyof ERROR_STATUS} code   one of the Contract 3 codes (unknown codes become "internal")
   * @param {string} [message]          plain-English, visitor-safe message (defaults per code)
   */
  constructor(code, message) {
    const known = Object.hasOwn(ERROR_STATUS, code) ? code : 'internal';
    super(message || ERROR_MESSAGES[known]);
    this.name = 'ScanError';
    this.code = known;
    this.httpStatus = ERROR_STATUS[known];
  }
}

export function isScanError(err) {
  return err instanceof ScanError;
}

/**
 * Turn anything thrown into the public JSON error shape. Unknown errors become
 * `internal` with the generic message, so stack traces and low-level details
 * never reach the client.
 * @returns {{ status: number, body: { ok: false, error: { code: string, message: string } } }}
 */
export function errorResponse(err) {
  const e = isScanError(err) ? err : new ScanError('internal');
  return {
    status: e.httpStatus,
    body: { ok: false, error: { code: e.code, message: e.message } },
  };
}
