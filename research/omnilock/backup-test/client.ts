import * as ccc from "@ckb-ccc/core";
import { JoyId } from "@ckb-ccc/joy-id";

type Eip1193 = { request(args: { method: string; params?: unknown[] }): Promise<unknown> };

const client = new ccc.ClientPublicTestnet();
const joyId = new JoyId.CkbSigner(client, "KeyWay backup test", `${location.origin}/favicon.ico`);
const $ = (id: string) => document.getElementById(id)!;
let joyIdAddress = "";
let evmAddress = "";

const message = (error: unknown) => error instanceof Error ? error.message : typeof error === "object" && error && "message" in error ? String(error.message) : String(error);

function step(id: string, state: "todo" | "busy" | "done" | "error", note = "") {
  const element = $(id);
  element.dataset.state = state;
  element.querySelector(".note")!.textContent = note;
  for (const button of element.querySelectorAll<HTMLButtonElement>("button:not(.small)")) button.disabled = state === "busy" || (state === "done" && !button.dataset.again);
}

function connected() {
  if (joyIdAddress || evmAddress) {
    $("step2").dataset.state = $("step2").dataset.state === "done" ? "done" : "todo";
    $("setup").textContent = `Make test account with ${[joyIdAddress && "JoyID", evmAddress && "EVM wallet"].filter(Boolean).join(" and ")}`;
  }
}

function showAccount(account: { address: string; transactionHash: string; balance: string }) {
  step("step2", "done", "");
  $("account").textContent = account.address;
  $("enable-tx").setAttribute("href", `https://testnet.explorer.nervos.org/transaction/${account.transactionHash}`);
  $("account-balance").textContent = `${account.balance} CKB`;
  $("step2-result").hidden = false;
  for (const id of ["step3", "step4"]) $(id).dataset.state = "todo";
}

async function refresh() {
  const status = await (await fetch("/api/status")).json();
  if (status.account) showAccount(status.account);
}

$("connect-joyid").onclick = async () => {
  step("step1", "busy", "Approve in the JoyID window…");
  try {
    await joyId.connect();
    joyIdAddress = await joyId.getRecommendedAddress();
    $("joyid").textContent = joyIdAddress;
    $("destination-joyid").textContent = joyIdAddress;
    step("step1", "todo", "");
    connected();
  } catch (error) {
    step("step1", "error", message(error));
  }
};

$("connect-evm").onclick = async () => {
  const ethereum = (window as unknown as { ethereum?: Eip1193 }).ethereum;
  if (!ethereum) return step("step1", "error", "No EVM wallet found in this browser. Open this page in a browser with your EVM wallet extension.");
  step("step1", "busy", "Approve in your EVM wallet…");
  try {
    const [account] = await ethereum.request({ method: "eth_requestAccounts" }) as string[];
    evmAddress = account;
    $("evm").textContent = evmAddress;
    step("step1", "todo", "");
    connected();
  } catch (error) {
    step("step1", "error", message(error));
  }
};

async function challenge(kind: "joyid" | "evm", address: string): Promise<{ text: string; challengeNonce: string }> {
  return (await fetch(`/api/challenge?kind=${kind}&address=${encodeURIComponent(address)}`)).json();
}

$("setup").onclick = async () => {
  if (!joyIdAddress && !evmAddress) return step("step2", "error", "Connect a backup first (step 1).");
  try {
    const backups: unknown[] = [];
    if (joyIdAddress) {
      step("step2", "busy", "Approve the message in the JoyID window…");
      const { text, challengeNonce } = await challenge("joyid", joyIdAddress);
      const signed = await joyId.signMessage(text);
      backups.push({ kind: "joyid", address: joyIdAddress, signature: signed.signature, identity: signed.identity, challengeNonce });
    }
    if (evmAddress) {
      step("step2", "busy", "Approve the message in your EVM wallet…");
      const { text, challengeNonce } = await challenge("evm", evmAddress);
      const ethereum = (window as unknown as { ethereum: Eip1193 }).ethereum;
      const signature = await ethereum.request({ method: "personal_sign", params: [ccc.hexFrom(new TextEncoder().encode(text)), evmAddress] }) as string;
      backups.push({ kind: "evm", address: evmAddress, signature, challengeNonce });
    }
    step("step2", "busy", "Turning recovery on and waiting for the chain (about a minute)…");
    const response = await fetch("/api/setup", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ backups }) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    await refresh();
  } catch (error) {
    step("step2", "error", message(error));
  }
};

$("refill").onclick = async () => {
  step("step4", "busy", "Sending 1,000 testnet CKB to the test account (about a minute)…");
  try {
    const response = await fetch("/api/refill", { method: "POST" });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    await refresh();
    step("step4", "todo", "Done. The test account has 1,000 CKB again.");
  } catch (error) {
    step("step4", "error", message(error));
  }
};

for (const button of document.querySelectorAll<HTMLButtonElement>("[data-copy]")) {
  button.onclick = async () => {
    await navigator.clipboard.writeText($(button.dataset.copy!).textContent ?? "");
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = "Copy"), 1500);
  };
}

void refresh();
