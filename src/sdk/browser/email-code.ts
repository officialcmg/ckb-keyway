/** Asks the user for the code KeyWay emailed them. Resolve undefined if they cancel. */
export type RequestEmailCode = (request: {
  reason: "transaction" | "settings" | "payment";
  error?: string;
  resend: () => Promise<void>;
}) => Promise<string | undefined>;

const WRONG_CODE = /isn't right|six-digit code/i;

/**
 * Sends the first code (except for settings, whose request already sent one), then asks the user until a
 * code is accepted, they cancel, or the backend refuses for another reason.
 */
export async function withEmailCode<T>(
  requestEmailCode: RequestEmailCode,
  reason: "transaction" | "settings" | "payment",
  send: () => Promise<void>,
  complete: (code: string) => Promise<T>,
): Promise<T> {
  if (reason !== "settings") await send();
  let error: string | undefined;
  for (;;) {
    const code = await requestEmailCode({ reason, error, resend: send });
    if (code === undefined) throw new Error("Email confirmation was cancelled");
    try {
      return await complete(code);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "";
      if (!WRONG_CODE.test(message)) throw cause;
      error = message;
    }
  }
}
