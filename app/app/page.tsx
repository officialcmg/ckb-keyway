import Link from "next/link";
import { AuthPanel } from "../auth-panel";

export default function WalletApp() {
  return (
    <main className="app-frame wallet-app">
      <header className="site-header">
        <Link className="brand-lockup brand-link" href="/">
          <span className="brand-mark" aria-hidden="true">K</span>
          <div><strong>CKB KeyWay</strong><span>Live Fiber wallet</span></div>
        </Link>
        <div className="network-pill"><span /> CKB testnet</div>
      </header>
      <section className="app-intro"><div><p className="eyebrow">Live SDK demo</p><h1>Move CKB through Fiber.</h1></div><p>Email-authenticated wallet recovery, channel liquidity, and routed payments in one reference app.</p></section>
      <AuthPanel />
      <footer className="site-footer"><span>CKB KeyWay</span><Link href="/">Project overview</Link><span>MIT licensed · Testnet prototype</span></footer>
    </main>
  );
}
