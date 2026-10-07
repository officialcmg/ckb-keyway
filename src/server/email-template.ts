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
