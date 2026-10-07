import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { createOtpEmailTemplate } from "../src/server/email-template.ts";

const [appName, otpVariable, outputDirectory] = process.argv.slice(2);
if (!appName || !otpVariable || !outputDirectory) {
  throw new Error('Usage: node --import tsx scripts/export-otp-email.mjs "Registered app name" "Preview code" /path/to/output');
}
const email = createOtpEmailTemplate(appName, otpVariable);
await mkdir(outputDirectory, { recursive: true });
await Promise.all([
  writeFile(path.join(outputDirectory, "otp.html"), email.html),
  writeFile(path.join(outputDirectory, "otp.txt"), email.plaintext),
  writeFile(path.join(outputDirectory, "subject.txt"), email.subject),
]);
console.log(`Generated OTP template files in ${outputDirectory}. These are preview files; live delivery uses Better Auth codes through Resend.`);
