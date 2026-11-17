// Login-code refusals after which the challenge can't be checked again, so only a new code helps. The SDK's login
// dialog recognizes them by "Request a new code" (src/sdk/browser/email-code.ts), so keep that phrase in each.

/** A wrong code that was its challenge's last try: the fifth, or the one try a code gets while checks are paused. */
export const LOGIN_CODE_ENDED = "Incorrect code, and it can't be tried again. Request a new code.";
/** A check refused while checks are paused, on a challenge that has had its try, when a new code would get one. */
export const LOGIN_CODE_PAUSED_NEW_CODE = "Too many incorrect codes have been tried for this email. Request a new code to try again.";
