"use client";

import type * as ccc from "@ckb-ccc/core";
import { useState, type FormEvent, type ReactNode } from "react";
import { AlertIcon, CheckIcon, ExternalIcon, SpinnerIcon } from "../_components/icons";
import { CopyButton } from "../_components/copy-button";
import {
  connectEvmBackup,
  openRescueAccount,
  planRescue,
  RESCUE_NETWORKS,
  rescueClient,
  rescueEntryForJoyId,
  sendRescue,
  signRescueWithEvm,
  signRescueWithJoyId,
  type RescueAccount,
  type RescueNetwork,
  type RescuePlan,
} from "../../src/rescue/rescue";
import type { EthereumProvider } from "../../src/sdk/browser/account-recovery";
import type { RecoveryListEntry } from "../../src/sdk/browser/recovery-list";
import { formatAsset } from "../../src/sdk/browser/tokens";

type Backup = { entry: RecoveryListEntry } & ({ kind: "evm"; ethereum: EthereumProvider } | { kind: "joyid"; signer: ccc.Signer });
type Busy = "account" | "evm" | "joyid" | "review" | "sign" | undefined;

const EXPLORERS: Record<RescueNetwork, string> = {
  testnet: "https://testnet.explorer.nervos.org",
  mainnet: "https://explorer.nervos.org",
};

const ckb = (shannons: bigint) => formatAsset(shannons, "ckb");

function message(error: unknown): string {
  const text = error instanceof Error ? error.message : typeof error === "object" && error && "message" in error ? String(error.message) : String(error);
  if (/user rejected|user denied|rejected the request|cancel/i.test(text)) return "The request was cancelled in your wallet";
  return text.replace(/\.$/, "");
}

export function RescueView() {
  const [network, setNetwork] = useState<RescueNetwork>("testnet");
  const [rpcUrl, setRpcUrl] = useState("");
  const [address, setAddress] = useState("");
  const [account, setAccount] = useState<RescueAccount>();
  const [backup, setBackup] = useState<Backup>();
  const [destination, setDestination] = useState("");
  const [plan, setPlan] = useState<RescuePlan>();
  const [sent, setSent] = useState<string>();
  const [busy, setBusy] = useState<Busy>();
  const [error, setError] = useState<{ step: "account" | "backup" | "review" | "sign"; text: string }>();
  // One client per lookup, so every later step talks to the node the account was read from.
  const [client, setClient] = useState<ccc.Client>();

  const run = async (step: NonNullable<typeof error>["step"], what: Busy, task: () => Promise<void>) => {
    setBusy(what);
    setError(undefined);
    try {
      await task();
    } catch (cause) {
      setError({ step, text: message(cause) });
    } finally {
      setBusy(undefined);
    }
  };

  const reset = (from: "account" | "backup" | "review") => {
    if (from === "account") { setAccount(undefined); setClient(undefined); }
    if (from !== "review") setBackup(undefined);
    setPlan(undefined);
    setSent(undefined);
    setError(undefined);
  };

  const lookUp = (event: FormEvent) => {
    event.preventDefault();
    reset("account");
    void run("account", "account", async () => {
      const next = rescueClient(network, rpcUrl);
      setAccount(await openRescueAccount(next, address));
      setClient(next);
    });
  };

  const connectEvm = () => void run("backup", "evm", async () => {
    reset("backup");
    const ethereum = (window as { ethereum?: EthereumProvider }).ethereum;
    const entry = await connectEvmBackup(account!, ethereum);
    setBackup({ kind: "evm", entry, ethereum: ethereum! });
  });

  const connectJoyId = () => void run("backup", "joyid", async () => {
    reset("backup");
    const { JoyId } = await import("@ckb-ccc/joy-id");
    const signer = new JoyId.CkbSigner(client!, "KeyWay rescue", `${window.location.origin}/icon.svg`);
    await signer.connect();
    const entry = rescueEntryForJoyId(account!, await signer.getRecommendedAddress());
    setBackup({ kind: "joyid", entry, signer });
  });

  const review = (event: FormEvent) => {
    event.preventDefault();
    reset("review");
    void run("review", "review", async () => setPlan(await planRescue(client!, account!, backup!.entry, destination)));
  };

  const sign = () => void run("sign", "sign", async () => {
    const signed = backup!.kind === "evm"
      ? await signRescueWithEvm(client!, account!, plan!, backup!.ethereum)
      : await signRescueWithJoyId(client!, account!, plan!, backup!.signer);
    setSent(await sendRescue(client!, signed));
  });

  const explorer = EXPLORERS[network];

  return (
    <div className="rescue-steps">
      <Step number={1} title="Your KeyWay address" done={Boolean(account)}>
        <form className="rescue-form" onSubmit={lookUp}>
          <div className="rescue-network" role="radiogroup" aria-label="Network">
            {(["testnet", "mainnet"] as const).map((value) => (
              <button key={value} type="button" role="radio" aria-checked={network === value} onClick={() => { setNetwork(value); reset("account"); }}>
                {value === "testnet" ? "Testnet" : "Mainnet (untested)"}
              </button>
            ))}
          </div>
          {network === "mainnet" && (
            <p className="rescue-warning"><AlertIcon /> KeyWay recovery runs on CKB testnet. The mainnet path is prepared but hasn&apos;t been tried yet.</p>
          )}
          <div className="field">
            <label htmlFor="rescue-address">KeyWay address</label>
            <span id="rescue-address-hint" className="field__hint">The address your account shows, or the one in the email sent when you turned recovery on. It starts with {RESCUE_NETWORKS[network].addressPrefix}1.</span>
            <textarea
              id="rescue-address"
              aria-describedby="rescue-address-hint"
              className="input rescue-address"
              rows={3}
              spellCheck={false}
              autoComplete="off"
              value={address}
              aria-invalid={error?.step === "account"}
              onChange={(event) => setAddress(event.target.value)}
              placeholder={`${RESCUE_NETWORKS[network].addressPrefix}1…`}
            />
          </div>
          <details className="rescue-node">
            <summary>CKB node</summary>
            <div className="field">
              <label htmlFor="rescue-node">Node URL</label>
              <span id="rescue-node-hint" className="field__hint">Any public CKB node with the indexer on, over HTTPS. Default: {RESCUE_NETWORKS[network].rpcUrl}</span>
              <input id="rescue-node" aria-describedby="rescue-node-hint" className="input" value={rpcUrl} onChange={(event) => setRpcUrl(event.target.value)} placeholder={RESCUE_NETWORKS[network].rpcUrl} spellCheck={false} />
            </div>
          </details>
          <button type="submit" className={`btn btn--route rescue-action${busy === "account" ? " btn--busy" : ""}`} disabled={!address.trim() || Boolean(busy)}>
            {busy === "account" ? <><SpinnerIcon /> Reading the chain</> : "Look up"}
          </button>
          {error?.step === "account" && <Problem text={error.text} />}
        </form>

        {account && (
          <div className="rescue-account">
            <dl className="detail-list">
              <div><dt>CKB</dt><dd>{ckb(account.ckb)}</dd></div>
              {account.tokens.map((token) => <div key={token.typeHash}><dt>Token</dt><dd>{token.amountText}</dd></div>)}
              {account.tokenCkb > 0n && <div><dt>Held by token cells</dt><dd>{ckb(account.tokenCkb)}</dd></div>}
              <div><dt>Recovery list</dt><dd>{ckb(account.adminList.cellOutput.capacity)}, stays</dd></div>
              {account.other.length > 0 && <div><dt>Other cells, not moved</dt><dd>{account.other.length} ({ckb(account.other.reduce((sum, cell) => sum + cell.cellOutput.capacity, 0n))})</dd></div>}
            </dl>
            <div className="rescue-backups">
              <h3>Backups on the recovery list</h3>
              <ul>
                {account.entries.map(({ backup: listed }) => (
                  <li key={`${listed.kind}:${listed.address}`}>
                    <span className="rescue-backups__kind">{listed.kind === "evm" ? "EVM wallet" : "JoyID"}</span>
                    <span className="mono rescue-backups__address">{listed.address}</span>
                  </li>
                ))}
              </ul>
            </div>
            {account.later > 0 && <p className="rescue-note">This address has more cells than one transaction moves. After this rescue, look up the address again to move the other {account.later}.</p>}
          </div>
        )}
      </Step>

      <Step number={2} title="Connect a backup" done={Boolean(backup)} disabled={!account}>
        {account && (
          <>
            <p className="rescue-copy">Connect one of the backups listed above. It only signs; nothing is sent until you approve the transaction in step 4.</p>
            <div className="rescue-buttons">
              <button type="button" className={`btn btn--outline${busy === "evm" ? " btn--busy" : ""}`} onClick={connectEvm} disabled={Boolean(busy)}>
                {busy === "evm" ? <><SpinnerIcon /> Waiting for the wallet</> : "EVM wallet"}
              </button>
              <button type="button" className={`btn btn--outline${busy === "joyid" ? " btn--busy" : ""}`} onClick={connectJoyId} disabled={Boolean(busy)}>
                {busy === "joyid" ? <><SpinnerIcon /> Waiting for JoyID</> : "JoyID"}
              </button>
            </div>
            {backup && (
              <p className="rescue-ok"><CheckIcon /> <span>{backup.kind === "evm" ? "EVM wallet" : "JoyID"} <span className="mono">{backup.entry.backup.address}</span> is on the list.</span></p>
            )}
            {error?.step === "backup" && <Problem text={error.text} />}
          </>
        )}
      </Step>

      <Step number={3} title="Where to send everything" done={Boolean(plan)} disabled={!backup}>
        {backup && (
          <form className="rescue-form" onSubmit={review}>
            <div className="field">
              <label htmlFor="rescue-destination">Destination address</label>
              <span id="rescue-destination-hint" className="field__hint">A CKB address you control with another wallet. Check it carefully: a rescue can&apos;t be undone.</span>
              <textarea
                id="rescue-destination"
                aria-describedby="rescue-destination-hint"
                className="input rescue-address"
                rows={3}
                spellCheck={false}
                autoComplete="off"
                value={destination}
                aria-invalid={error?.step === "review"}
                onChange={(event) => { setDestination(event.target.value); setPlan(undefined); }}
                placeholder={`${RESCUE_NETWORKS[network].addressPrefix}1…`}
              />
            </div>
            <button type="submit" className={`btn btn--route rescue-action${busy === "review" ? " btn--busy" : ""}`} disabled={!destination.trim() || Boolean(busy)}>
              {busy === "review" ? <><SpinnerIcon /> Building the transaction</> : "Review"}
            </button>
            {error?.step === "review" && <Problem text={error.text} />}
          </form>
        )}
      </Step>

      <Step number={4} title="Review and sign" done={Boolean(sent)} disabled={!plan}>
        {plan && account && (
          <div className="rescue-review">
            <dl className="detail-list">
              <div><dt>From</dt><dd className="mono">{account.address}</dd></div>
              <div><dt>To</dt><dd className="mono">{plan.destination}</dd></div>
              <div><dt>CKB arriving</dt><dd>{ckb(plan.ckb)}</dd></div>
              {plan.tokens.map((token, index) => (
                <div key={`${token.typeHash}:${index}`}><dt>Token</dt><dd>{token.amountText} <span className="rescue-muted">in a cell holding {ckb(token.capacity)}</span></dd></div>
              ))}
              <div><dt>Network fee</dt><dd>{ckb(plan.fee)}</dd></div>
              <div><dt>Signed by</dt><dd>{plan.entry.backup.kind === "evm" ? "EVM wallet" : "JoyID"} <span className="mono">{plan.entry.backup.address}</span></dd></div>
              <div><dt>Network</dt><dd>{RESCUE_NETWORKS[network].label}</dd></div>
            </dl>
            <p className="rescue-note">
              Stays at your KeyWay address: the recovery list ({ckb(account.adminList.cellOutput.capacity)}), which holds the list of
              backups and can&apos;t be moved by a rescue
              {account.other.length > 0 ? `, and ${account.other.length} other cell${account.other.length === 1 ? "" : "s"} this page doesn't move` : ""}.
            </p>
            {plan.entry.backup.kind === "evm" && (
              <p className="rescue-copy">Your EVM wallet will ask you to sign a message that reads &ldquo;CKB transaction: 0x…&rdquo;. That message approves exactly this transaction.</p>
            )}
            {!sent && (
              <button type="button" className={`btn btn--route btn--lg rescue-action${busy === "sign" ? " btn--busy" : ""}`} onClick={sign} disabled={Boolean(busy)}>
                {busy === "sign" ? <><SpinnerIcon /> Waiting for the signature</> : "Sign and send"}
              </button>
            )}
            {error?.step === "sign" && <Problem text={error.text} />}
            {sent && (
              <div className="rescue-sent" role="status">
                <p className="rescue-ok"><CheckIcon /> Sent. It usually confirms within a minute.</p>
                <div className="copy-well">
                  <span className="copy-well__value">{sent}</span>
                  <CopyButton value={sent} label="Copy transaction hash" />
                </div>
                <a className="link rescue-explorer" href={`${explorer}/transaction/${sent}`} target="_blank" rel="noreferrer">
                  View in explorer <ExternalIcon />
                </a>
              </div>
            )}
          </div>
        )}
      </Step>
    </div>
  );
}

function Step({ number, title, done, disabled, children }: { number: number; title: string; done: boolean; disabled?: boolean; children: ReactNode }) {
  return (
    <section className={`card rescue-step${disabled ? " is-disabled" : ""}`} aria-labelledby={`rescue-step-${number}`}>
      <div className="rescue-step__head">
        <span className="rescue-step__number" aria-hidden="true">{done ? <CheckIcon size={14} /> : number}</span>
        <h2 id={`rescue-step-${number}`}>{title}</h2>
      </div>
      {children}
    </section>
  );
}

function Problem({ text }: { text: string }) {
  return <p className="field-error" role="alert"><AlertIcon /> {text}</p>;
}
