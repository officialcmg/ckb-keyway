import Link from "next/link";
import { AuthPanel } from "../auth-panel";

export default async function WalletApp({ searchParams }: { searchParams: Promise<{ mode?: string }> }) {
  const nodeMode = process.env.KEYWAY_STAGING_FRONTEND === "1" && (await searchParams).mode === "managed"
    ? "managed"
    : "browser";
  return (
    <main className="app-frame wallet-app">
      <header className="site-header">
        <Link className="brand-lockup brand-link" href="/">
          <span className="brand-mark" aria-hidden="true">K</span>
          <div><strong>CKB KeyWay</strong><span>Live Fiber wallet</span></div>
        </Link>
        <div className="app-links"><a href="https://ckb-keyway-docs.vercel.app">Docs</a><a href="https://www.npmjs.com/package/@ckb-keyway/react">npm</a><div className="network-pill"><span /> CKB testnet</div></div>
      </header>
      <section className="app-intro"><div><p className="eyebrow">Live SDK demo</p><h1>Move CKB through Fiber.</h1></div><p>Email-authenticated wallet recovery, channel liquidity, and routed payments in one reference app.</p></section>
      <AuthPanel nodeMode={nodeMode} />
      <footer className="site-footer"><span>CKB KeyWay</span><Link href="/">Project overview</Link><a href="https://ckb-keyway-docs.vercel.app">Docs</a><a href="https://www.npmjs.com/package/@ckb-keyway/react">npm</a></footer>
    </main>
  );
}
