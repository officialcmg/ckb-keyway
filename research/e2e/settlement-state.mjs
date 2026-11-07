// The browser-settlement run's saved state (.evidence/settlement-state.json). It is kept across restarts so a run
// that waits hours through the commitment delay can be followed up, but everything in it belongs to one account and
// one channel: a new run never inherits a finished run's state, and a new account or channel drops what the old
// one found (its commitment above all, which would stop the new channel from being followed).

/** What belongs to one channel. */
const CHANNEL_FIELDS = ["channelId", "funding", "feeReserveTxHash", "forceCloseAt", "commitment"];
/** What belongs to one account, its channel's fields included. */
const ACCOUNT_FIELDS = ["email", "password", "address", "userScript", ...CHANNEL_FIELDS];

/** The state to start from: what the file holds, unless that run finished (or the file is unreadable). */
export function loadSettlementState(text) {
  if (text === undefined) return {};
  let saved;
  try { saved = JSON.parse(text); } catch { return {}; }
  if (!saved || typeof saved !== "object" || Array.isArray(saved) || saved.finished) return {};
  return saved;
}

/**
 * An unfinished run that got as far as opening its channel: a restart signs in to the same account and carries on with
 * the same channel (force-closing it if that hadn't happened yet) instead of setting up new ones.
 */
export function resumableRun(state) {
  return !state.finished && Boolean(state.email && state.password && state.address && state.channelId && state.funding);
}

/**
 * What a start of the script does with the saved state: resume (keeping the browser profile, which holds the device
 * ID and the node's channel databases) or start fresh, and which setup steps still have to run.
 */
export function startupPlan(state) {
  if (!resumableRun(state)) return { resume: false, keepProfile: false, setUp: true, forceClose: true };
  return { resume: true, keepProfile: true, setUp: false, forceClose: !state.forceCloseAt };
}

/** Records the run's account. A different account than the saved one starts from nothing. */
export function forAccount(state, address) {
  if (state.address !== address) for (const field of [...ACCOUNT_FIELDS, "finished"]) delete state[field];
  state.address = address;
  return state;
}

/** Records the run's channel. A different channel than the saved one drops the old channel's findings. */
export function forChannel(state, channelId) {
  if (state.channelId !== channelId) for (const field of [...CHANNEL_FIELDS, "finished"]) delete state[field];
  state.channelId = channelId;
  return state;
}
