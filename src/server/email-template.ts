function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!);
}

/** The authentication provider generates the code; this module only renders it. */
export function createOtpEmailTemplate(appName: string, codeVariable: string) {
  const name = appName.trim().slice(0, 64);
  if (!name || !codeVariable.trim()) throw new Error("Application name and login code are required");
  const safeName = escapeHtml(name);
  const code = escapeHtml(codeVariable);
  return {
    subject: `Your login code for ${name}`,
    plaintext: `Log in to ${name}\n\nYour code is ${codeVariable}\n\nThis code expires in 10 minutes. Never share it with anyone. If you did not request it, you can ignore this email.\n\nSecured by CKB KeyWay`,
    html: `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Log in to ${safeName}</title></head>
<body style="margin:0;padding:0;background:#f3f4f6;color:#111827;font-family:Arial,Helvetica,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px;background:#ffffff;border-radius:16px"><tr><td align="center" style="padding:40px 24px">
<p style="margin:0 0 12px;color:#6b7280;font-size:14px">${safeName}</p>
<h1 style="margin:0;font-size:22px;line-height:32px;font-weight:500">Log in to <strong>${safeName}</strong></h1>
<hr style="margin:24px 0;border:0;border-top:1px solid #e5e7eb">
<p style="margin:0 0 16px;font-size:14px">Your login code</p>
<table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="padding:20px 28px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:12px;font-family:monospace;font-size:40px;line-height:48px;font-weight:700;letter-spacing:6px;color:#111827">${code}</td></tr></table>
<p style="margin:20px 0 0;font-size:14px;line-height:22px">This code expires in 10 minutes.<br>Never share this code with anyone.</p>
<hr style="margin:28px 0;border:0;border-top:1px solid #e5e7eb">
<p style="margin:0;font-size:14px;line-height:22px">Didn't request this? You can safely ignore this email.</p>
</td></tr></table>
<p style="margin:20px 0 0;color:#6b7280;font-size:12px">Secured by <strong>CKB KeyWay</strong></p>
</td></tr></table></body></html>`,
  };
}

/**
 * A confirmation code for an action the user must approve from their inbox, such as a large transaction.
 * The summary lines are written by the backend from its own decoding, never from browser input.
 */
export function createConfirmationEmailTemplate(appName: string, code: string, heading: string, summary: string[]) {
  const name = appName.trim().slice(0, 64);
  if (!name || !/^\d{6}$/.test(code) || !heading.trim()) throw new Error("Application name, heading and a six-digit code are required");
  const safeName = escapeHtml(name);
  const safeHeading = escapeHtml(heading);
  const lines = summary.slice(0, 12).map((line) => line.slice(0, 160));
  const rows = lines.map((line) => `<tr><td style="padding:6px 0;border-top:1px solid #e5e7eb;font-size:14px;line-height:20px;text-align:left">${escapeHtml(line)}</td></tr>`).join("");
  return {
    subject: `${heading} in ${name}`,
    plaintext: `${heading} in ${name}\n\n${lines.join("\n")}\n\nYour confirmation code is ${code}\n\nThis code expires in 10 minutes. Only enter it if you started this action. If you didn't, don't share the code, and sign in to ${name} to check your account.\n\nSecured by CKB KeyWay`,
    html: `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${safeHeading}</title></head>
<body style="margin:0;padding:0;background:#f3f4f6;color:#111827;font-family:Arial,Helvetica,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px;background:#ffffff;border-radius:16px"><tr><td align="center" style="padding:40px 24px">
<p style="margin:0 0 12px;color:#6b7280;font-size:14px">${safeName}</p>
<h1 style="margin:0;font-size:22px;line-height:32px;font-weight:500">${safeHeading}</h1>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0">${rows}</table>
<p style="margin:0 0 16px;font-size:14px">Your confirmation code</p>
<table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="padding:20px 28px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:12px;font-family:monospace;font-size:40px;line-height:48px;font-weight:700;letter-spacing:6px;color:#111827">${code}</td></tr></table>
<p style="margin:20px 0 0;font-size:14px;line-height:22px">This code expires in 10 minutes.<br>Only enter it if you started this action.</p>
<hr style="margin:28px 0;border:0;border-top:1px solid #e5e7eb">
<p style="margin:0;font-size:14px;line-height:22px">Didn't start this? Don't share the code, and sign in to ${safeName} to check your account.</p>
</td></tr></table>
<p style="margin:20px 0 0;color:#6b7280;font-size:12px">Secured by <strong>CKB KeyWay</strong></p>
</td></tr></table></body></html>`,
  };
}

/** Where a recovery account's backups can move its funds without KeyWay. */
export const RESCUE_PAGE_URL = "https://ckbkeyway.dev/rescue";

/**
 * Sent after recovery is turned on and after each backup change, so the user has their address and the way
 * out in their inbox even if KeyWay is gone. No code: it only reports what happened.
 */
export function createRecoveryNoticeEmailTemplate(appName: string, notice: { heading: string; address: string; backups: string[]; network: string }) {
  const name = appName.trim().slice(0, 64);
  if (!name || !notice.heading.trim() || !/^ck[bt]1[0-9a-z]+$/.test(notice.address)) throw new Error("Application name, heading and a CKB address are required");
  const safeName = escapeHtml(name);
  const safeHeading = escapeHtml(notice.heading);
  const backups = notice.backups.slice(0, 12).map((backup) => backup.slice(0, 160));
  const rescue = `If ${name} or KeyWay is ever unavailable, any of these backups can move everything at this address to a wallet you choose at ${RESCUE_PAGE_URL}. It needs only this address and the backup.`;
  const rows = backups.map((backup) => `<tr><td style="padding:6px 0;border-top:1px solid #e5e7eb;font-size:14px;line-height:20px;text-align:left">${escapeHtml(backup)}</td></tr>`).join("");
  return {
    subject: `${notice.heading} in ${name}`,
    plaintext: `${notice.heading} in ${name}\n\nYour account address (${notice.network}):\n${notice.address}\n\nBackups:\n${backups.join("\n")}\n\n${rescue}\n\nKeep this email. If you didn't make this change, sign in to ${name} and check your backups now.\n\nSecured by CKB KeyWay`,
    html: `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${safeHeading}</title></head>
<body style="margin:0;padding:0;background:#f3f4f6;color:#111827;font-family:Arial,Helvetica,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px;background:#ffffff;border-radius:16px"><tr><td align="center" style="padding:40px 24px">
<p style="margin:0 0 12px;color:#6b7280;font-size:14px">${safeName}</p>
<h1 style="margin:0;font-size:22px;line-height:32px;font-weight:500">${safeHeading}</h1>
<p style="margin:24px 0 8px;font-size:14px;text-align:left">Your account address (${escapeHtml(notice.network)})</p>
<p style="margin:0;padding:12px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:8px;font-family:monospace;font-size:13px;line-height:20px;word-break:break-all;text-align:left">${escapeHtml(notice.address)}</p>
<p style="margin:24px 0 0;font-size:14px;text-align:left">Backups</p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:8px 0 24px">${rows}</table>
<p style="margin:0;font-size:14px;line-height:22px;text-align:left">If ${safeName} or KeyWay is ever unavailable, any of these backups can move everything at this address to a wallet you choose at <a href="${RESCUE_PAGE_URL}" style="color:#2f54e8">${RESCUE_PAGE_URL.replace("https://", "")}</a>. It needs only this address and the backup.</p>
<hr style="margin:28px 0;border:0;border-top:1px solid #e5e7eb">
<p style="margin:0;font-size:14px;line-height:22px">Keep this email. If you didn't make this change, sign in to ${safeName} and check your backups now.</p>
</td></tr></table>
<p style="margin:20px 0 0;color:#6b7280;font-size:12px">Secured by <strong>CKB KeyWay</strong></p>
</td></tr></table></body></html>`,
  };
}
