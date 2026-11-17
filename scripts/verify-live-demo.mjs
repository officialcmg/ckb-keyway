import assert from "node:assert/strict";
import fs from "node:fs/promises";
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const api="https://keyway-api-production.up.railway.app/api/v1/keyway", origin="https://www.ckbkeyway.dev", appId="keyway_H3jyHCLd0tDqJ0qpEot8j3zB";
async function json(url, body, token, headers = {}) {
  let response;
  for (let attempt = 0; attempt < 4; attempt++) {
    response = await fetch(url, { method: body ? "POST" : "GET", headers: { "Content-Type": "application/json", ...(url.startsWith(api) ? { Origin: origin, "X-KeyWay-App-Id": appId } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(30_000) });
    if (response.status !== 429 || attempt === 3) break;
    await new Promise(resolve => setTimeout(resolve, 20_000));
  }
  if (!response.ok) throw new Error(`Verification request failed: ${response.status} ${new URL(url).pathname}`);
  if (response.status === 204) return;
  return response.json();
}
async function markSeen(mailbox) {
  for (const message of (await json("https://api.mail.tm/messages", undefined, mailbox.token))["hydra:member"]) mailbox.seen.add(message.id);
}
async function nextCode(mailbox, digits = 6) {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    for (const message of (await json("https://api.mail.tm/messages", undefined, mailbox.token))["hydra:member"]) {
      if (mailbox.seen.has(message.id)) continue;
      const full = await json(`https://api.mail.tm/messages/${message.id}`, undefined, mailbox.token);
      const code = `${full.text ?? ""}`.match(new RegExp(`(?:Your confirmation code is|Your code is)\\s+(\\d{${digits}})\\b`, "i"))?.[1];
      if (code) { mailbox.seen.add(message.id); return code; }
    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  throw new Error(`Disposable ${digits}-digit email did not arrive within two minutes`);
}
// Drive the actual dialogs; never log mailbox addresses, codes, sessions or browser storage.
async function signIn(page, mailbox, live = false) {
  await markSeen(mailbox);
  if (live) await page.getByRole("button", { name: "Sign in with email", exact: true }).click();
  else {
    await page.waitForFunction(() => window.probe?.auth.ready);
    await page.evaluate(() => { window.probe.auth.login(); });
  }
  await page.locator('input[type="email"]').fill(mailbox.email);
  for (let attempt = 0; attempt < 5; attempt++) {
    const sent = page.waitForResponse(response => response.url().endsWith("/auth/send-code") && response.request().method() === "POST");
    await page.locator('input[type="email"]').press("Enter");
    const response = await sent;
    if (response.ok()) break;
    if (response.status() !== 429 || attempt === 4) throw new Error(`UI sign-in request failed: HTTP ${response.status()}`);
    const body = await response.json();
    const seconds = Number(String(body.error ?? "").match(/(?:in|wait) (\d+) seconds/i)?.[1] ?? 60);
    console.log(`Sign-in cooldown: waiting ${seconds + 1}s before retry`);
    await page.waitForTimeout((seconds + 1) * 1000);
  }
  await page.locator('input[autocomplete="one-time-code"]').fill(await nextCode(mailbox));
}
async function rpc(method, params) {
  const result = await json("https://testnet.ckb.dev/", { id: 1, jsonrpc: "2.0", method, params });
  if (result.error) throw new Error(`CKB ${method}: ${result.error.message}`);
  return result.result;
}
async function committed(hash) {
  for (let attempt = 0; attempt < 90; attempt++) {
    const result = await rpc("get_transaction", [hash]);
    if (result?.tx_status.status === "committed") return result;
    if (result?.tx_status.status === "rejected") throw new Error(`CKB transaction rejected: ${hash}`);
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  throw new Error(`CKB transaction not committed within three minutes: ${hash}`);
}

const directory=process.env.EVIDENCE_DIRECTORY;
if (!directory) throw new Error("EVIDENCE_DIRECTORY must contain the disposable account records from verify-live-wallet.mjs");
const browserMode=process.env.FIBER_MODE==="browser";
const account=JSON.parse(await fs.readFile(`${directory}/account-1.json`));
const recipient=JSON.parse(await fs.readFile(`${directory}/account-2.json`));
const mailbox={email:account.email, token:(await json("https://api.mail.tm/token",{address:account.email,password:account.password})).token,seen:new Set()};
const context=await chromium.launchPersistentContext(`${directory}/actual-app-${browserMode?"browser":"hosted"}`,{headless:true,channel:"chrome"});
const page=await context.newPage();page.setDefaultTimeout(120000);
async function evidence(event,details={}){const row={at:new Date().toISOString(),event,...details};await fs.appendFile(`${directory}/results.jsonl`,JSON.stringify(row)+"\n");console.log(JSON.stringify(row));}
async function approveUntil(done,buttons){
 const deadline=Date.now()+240000;
 let nextProgress=Date.now()+30000;
 while(Date.now()<deadline){
  if(await done())return;
  if(Date.now()>=nextProgress){console.log("Waiting for app dialog",JSON.stringify(await page.getByRole("dialog").getByRole("heading").allTextContents()));nextProgress=Date.now()+30000;}
  const code=page.locator('input[autocomplete="one-time-code"]');
  if(await code.isVisible()&&await code.isEnabled()&&!await code.inputValue())await code.fill(await nextCode(mailbox,Number(await code.getAttribute("maxlength"))||8));
  for(const name of buttons){const button=page.getByRole("dialog").getByRole("button",{name,exact:true});if(await button.isVisible()&&await button.isEnabled()){
   if(name==="Approve"){const text=await page.getByRole("dialog").innerText();assert.ok(text.includes(recipient.address)&&text.includes("100 CKB")&&text.includes("CKB testnet"),"Approval must show the disposable recipient, amount, and testnet");}
   await button.click();
  }}
  const errors=(await page.getByRole("alert").allTextContents()).filter(text=>text.trim());if(errors.length)throw new Error(errors.join("; ").replaceAll(account.email,"[disposable email]"));
  await page.waitForTimeout(500);
 }
 throw new Error("Actual app operation timed out");
}
try{
 if(process.env.LOCAL_APP==="1")await page.route(`${origin}/**`,async route=>{
  const u=new URL(route.request().url());u.protocol="http:";u.host="127.0.0.1:3137";
  const response=await route.fetch({url:u.href});await route.fulfill({response});
 });
 await page.goto(`${origin}/app${browserMode?"?mode=browser":""}`,{waitUntil:"domcontentloaded"});
 if(!await page.getByRole("button",{name:"Sign out",exact:true}).isVisible())await signIn(page,mailbox,true);
 await page.getByRole("button",{name:"Start Fiber",exact:true}).waitFor({timeout:180000});
 assert.equal(await page.locator(".copy-well__value").first().innerText(),account.address);
 await evidence("PASS actual app wallet-only login",{mode:browserMode?"browser":"hosted",frontend:process.env.LOCAL_APP==="1"?"local candidate production build":"deployed site"});
 await page.getByRole("button",{name:"Start Fiber",exact:true}).click();
 await page.getByText(browserMode?"Running · in-browser node":"Running · hosted node",{exact:true}).waitFor({timeout:240000});
 await evidence("PASS actual app node start");
 const send=page.locator("section").filter({has:page.getByRole("heading",{name:"Send CKB",exact:true})});
 await send.getByLabel("To address",{exact:true}).fill(recipient.address);
 await send.locator('input[inputmode="decimal"]').first().fill("100");
 await markSeen(mailbox);await send.getByRole("button",{name:"Send",exact:true}).click();
 await approveUntil(()=>send.locator(".demo-tx-link").isVisible(),["Continue","Approve"]);
 const hash=(await send.locator(".demo-tx-link").getAttribute("href")).split("/").pop();await committed(hash);
 await evidence("PASS actual app 100 CKB send committed",{transactionHash:hash});
 await markSeen(mailbox);await send.getByLabel("Message",{exact:true}).fill("KeyWay disposable live verification");
 await send.getByRole("button",{name:"Sign message",exact:true}).click();
 await approveUntil(()=>send.getByText("Signed, and verified with CCC's verifyMessage",{exact:false}).isVisible(),["Sign","Continue","Approve"]);
 await evidence("PASS actual app message signature verified");
 await page.getByRole("button",{name:"Sign out",exact:true}).click();
 await page.getByRole("button",{name:"Sign in with email",exact:true}).waitFor({timeout:180000});
 await evidence("PASS actual app transactional logout");
}catch(e){await evidence("FAIL actual app verification",{error:e.message.replaceAll(account.email,"[disposable email]"),headings:await page.getByRole("heading").allTextContents(),alerts:(await page.getByRole("alert").allTextContents()).map(text=>text.replaceAll(account.email,"[disposable email]"))});throw e;}
finally{
 try{
  if(await page.getByRole("button",{name:"Sign out",exact:true}).isVisible().catch(()=>false)){
   await page.keyboard.press("Escape");await page.getByRole("button",{name:"Sign out",exact:true}).click();await page.getByRole("button",{name:"Sign in with email",exact:true}).waitFor({timeout:180000});
  }
 }finally{
  await context.close();
 }
}
