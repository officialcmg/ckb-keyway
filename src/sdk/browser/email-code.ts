export type EmailCodeReason = "transaction" | "settings" | "payment" | "recovery" | "recovery-backup";

/** Asks the user for the code KeyWay emailed them. Resolve undefined if they cancel. */
export type RequestEmailCode = (request: {
  reason: EmailCodeReason;
  error?: string;
  resend: () => Promise<void>;
  /** The address KeyWay sent the code to, when it reports one. */
  sentTo?: string;
  /**
   * Checks a code with KeyWay while the prompt stays open. Resolves once the code is accepted and the action
   * has run (then resolve the prompt with that code); rejects with the reason to show otherwise. Prompts that
   * don't use it can resolve with the code as before.
   */
  verify?: (code: string) => Promise<void>;
}) => Promise<string | undefined>;

/** Refusals the user can fix in the same prompt: a wrong or malformed code, or one to replace with a new one. */
const RETRY_CODE = /isn't right|six-digit code|request a new one/i;
const REQUEST_EXPIRED = /request expired/i;

/** Whether the user can try again in the same prompt, by entering another code or sending a new one. */
export function canRetryCode(message: string): boolean {
  return RETRY_CODE.test(message);
}

/** Whether the approval behind the prompt is gone, so only starting again helps. */
export function isRequestExpired(message: string): boolean {
  return REQUEST_EXPIRED.test(message);
}

const messageOf = (cause: unknown) => cause instanceof Error ? cause.message : "";

function sentAddress(response: unknown): string | undefined {
  const sentTo = (response as { sentTo?: unknown } | undefined)?.sentTo;
  return typeof sentTo === "string" && sentTo ? sentTo : undefined;
}

/**
 * Sends the first code (except for settings, whose request already sent one, passed as `sent`), then asks the
 * user until a code is accepted, they cancel, or the backend refuses for another reason. The prompt can check
 * each code itself through `verify`, staying open until KeyWay answers.
 */
export async function withEmailCode<T>(
  requestEmailCode: RequestEmailCode,
  reason: EmailCodeReason,
  send: () => Promise<unknown>,
  complete: (code: string) => Promise<T>,
  sent?: unknown,
): Promise<T> {
  const sentTo = sentAddress(reason === "settings" ? sent : await send());
  let accepted: { value: T } | undefined;
  let refused: { cause: unknown } | undefined;
  let checking: Promise<void> | undefined;
  const resend = async () => {
    try {
      await send();
    } catch (cause) {
      if (isRequestExpired(messageOf(cause))) refused = { cause };
      throw cause;
    }
  };
  const verify = (code: string) => {
    if (accepted) return Promise.resolve();
    if (refused) return Promise.reject(refused.cause);
    checking ??= complete(code).then((value) => { accepted = { value }; }, (cause) => {
      if (!canRetryCode(messageOf(cause))) refused = { cause };
      throw cause;
    }).finally(() => { checking = undefined; });
    return checking;
  };
  let error: string | undefined;
  for (;;) {
    const code = await requestEmailCode({ reason, error, resend, sentTo, verify });
    // A check still running when the prompt closes decides the outcome, so an accepted code is never lost.
    await checking?.catch(() => undefined);
    if (accepted) return accepted.value;
    if (refused) throw refused.cause;
    if (code === undefined) throw new Error("Email confirmation was cancelled");
    try {
      return await complete(code);
    } catch (cause) {
      const message = messageOf(cause);
      if (!canRetryCode(message)) throw cause;
      error = message;
    }
  }
}
