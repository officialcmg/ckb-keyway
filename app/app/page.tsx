import Link from "next/link";
import { AuthPanel } from "../auth-panel";

export default async function WalletApp({ searchParams }: { searchParams: Promise<{ mode?: string }> }) {
  const nodeMode = (await searchParams).mode === "browser"
    ? "browser"
    : "managed";
  return (
    <main className="app-frame wallet-app">
      <header className="site-header">
        <Link className="brand-lockup brand-link" href="/">
          <span className="brand-mark" aria-hidden="true">K</span>
          <div><strong>CKB KeyWay</strong><span>Live Fiber wallet</span></div>
        </Link>
        <div className="app-links"><Link href={nodeMode === "managed" ? "/app?mode=browser" : "/app"}>{nodeMode === "managed" ? "Browser wallet" : "Managed wallet"}</Link><a href="https://docs.ckbkeyway.dev">Docs</a><a href="https://www.npmjs.com/package/@ckb-keyway/react">npm</a><div className="network-pill"><span /> CKB testnet</div></div>
      </header>
      <section className="app-intro"><div><p className="eyebrow">{nodeMode === "managed" ? "Managed node demo" : "Browser node demo"}</p><h1>Move CKB through Fiber.</h1></div><p>{nodeMode === "managed" ? "KeyWay keeps your testnet node online. Existing browser channels stay in the browser wallet; switching modes does not migrate channels." : "Your Fiber node runs in this browser. Log out explicitly to back up its state before changing devices."}</p></section>
      <AuthPanel nodeMode={nodeMode} />
      <footer className="site-footer"><span>CKB KeyWay</span><Link href="/">Project overview</Link><a href="https://docs.ckbkeyway.dev">Docs</a><a href="https://www.npmjs.com/package/@ckb-keyway/react">npm</a></footer>
    </main>
  );
}
