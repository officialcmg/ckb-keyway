import Link from "next/link";

const developerSteps = [
  ["01", "Authenticate", "Email OTP opens the wallet without a seed phrase."],
  ["02", "Recover", "The same email recovers the same CKB and Fiber identity."],
  ["03", "Route", "Create channels, invoices, and routed Fiber payments from React."],
] as const;

export default function Home() {
  return (
    <main className="landing-page">
      <nav className="landing-nav">
        <Brand />
        <div><a href="#sdk">SDK</a><a href="#security">Security</a><Link className="nav-cta" href="/app">Launch demo</Link></div>
      </nav>

      <section className="landing-hero">
        <div className="hero-copy">
          <p className="eyebrow">Wallet infrastructure for CKB Fiber</p>
          <h1>Email in.<br /><span>Fiber ready.</span></h1>
          <p className="hero-lede">Give any React app an email-authenticated CKB wallet and instant Fiber payments without asking users to handle private keys.</p>
          <div className="hero-actions"><Link className="primary-link" href="/app">Try the live wallet</Link><a className="secondary-link" href="#sdk">See the SDK flow</a></div>
          <p className="testnet-note"><span /> Running on CKB testnet</p>
        </div>
        <div className="route-visual" aria-label="CKB KeyWay product flow">
          <div className="route-line" aria-hidden="true" />
          {developerSteps.map(([number, title, copy]) => (
            <article key={number}><span>{number}</span><div><strong>{title}</strong><p>{copy}</p></div></article>
          ))}
        </div>
      </section>

      <section className="pitch-strip" aria-label="Key product outcomes">
        <div><strong>One login</strong><span>Email OTP</span></div>
        <div><strong>One identity</strong><span>Recoverable CKB wallet</span></div>
        <div><strong>One integration</strong><span>Fiber channels and payments</span></div>
      </section>

      <section className="sdk-section" id="sdk">
        <div className="section-copy"><p className="eyebrow">Built for developers</p><h2>Fiber functionality behind one React provider.</h2><p>KeyWay owns the difficult path from authentication to wallet recovery, browser-node startup, channel funding, and routed payments. Your app keeps control of its product experience.</p></div>
        <div className="code-card">
          <div><span /><span /><span /><small>app.tsx</small></div>
          <pre><code>{`<KeyWayProvider appName="Your app">
  <YourApp />
</KeyWayProvider>

const { login, connection } = useKeyWay();

await connection.keyway.sendPayment({
  invoice,
});`}</code></pre>
        </div>
      </section>

      <section className="trust-section" id="security">
        <div><p className="eyebrow">The trust model</p><h2>Keys are infrastructure, not UI.</h2></div>
        <div className="trust-grid">
          <article><span>CKB</span><h3>Lit-authorized funding</h3><p>The CKB key is controlled through programmable Lit authorization instead of being exposed to the app.</p></article>
          <article><span>Fiber</span><h3>Browser-local node</h3><p>Each wallet runs its Fiber node in the browser and keeps channel state on that device.</p></article>
          <article><span>React</span><h3>SDK-owned lifecycle</h3><p>Login, recovery, connection, invoices, payments, and channel operations share one predictable API.</p></article>
        </div>
      </section>

      <section className="landing-cta"><div><p className="eyebrow">Live proof, not slides</p><h2>Open a wallet. Fund a channel. Pay an invoice.</h2></div><Link className="primary-link dark" href="/app">Launch CKB KeyWay</Link></section>
      <footer className="landing-footer"><Brand /><span>MIT licensed · Testnet prototype</span><a href="https://github.com/officialchrismg" target="_blank" rel="noreferrer">GitHub</a></footer>
    </main>
  );
}

function Brand() {
  return <div className="brand-lockup"><span className="brand-mark" aria-hidden="true">K</span><div><strong>CKB KeyWay</strong><span>Email-native Fiber wallet</span></div></div>;
}
