import Link from "next/link";

const developerSteps = [
  ["01", "Authenticate", "Email OTP opens a CKB account with no wallet setup."],
  ["02", "Recover", "The same email recovers the same CKB and Fiber identity."],
  ["03", "Route", "Create channels, invoices, and routed Fiber payments from React."],
] as const;

export default function Home() {
  return (
    <main className="landing-page">
      <nav className="landing-nav">
        <Brand />
        <div><a href="#sdk">SDK</a><a href="#security">Security</a><a href="https://ckb-keyway-docs.vercel.app">Docs</a><a href="https://www.npmjs.com/package/@ckb-keyway/react">npm</a><Link className="nav-cta" href="/app">Launch demo</Link></div>
      </nav>

      <section className="landing-hero">
        <div className="hero-copy">
          <p className="eyebrow">Wallet infrastructure for CKB Fiber</p>
          <h1>Email in.<br /><span>Fiber ready.</span></h1>
          <p className="hero-lede">Give any React app email-native CKB accounts and instant Fiber payments, so users can start with the identity they already have.</p>
          <div className="hero-actions"><Link className="primary-link" href="/app">Try the live wallet</Link><a className="secondary-link" href="https://ckb-keyway-docs.vercel.app">Read the docs</a></div>
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
          <pre><code><span className="syntax-tag">&lt;KeyWayProvider</span> <span className="syntax-attr">appName</span>=<span className="syntax-string">&quot;Your app&quot;</span><span className="syntax-tag">&gt;</span>{`\n  `}<span className="syntax-tag">&lt;YourApp /&gt;</span>{`\n`}<span className="syntax-tag">&lt;/KeyWayProvider&gt;</span>{`\n\n`}<span className="syntax-keyword">const</span>{` { `}<span className="syntax-variable">login</span>{`, `}<span className="syntax-variable">connection</span>{` } = `}<span className="syntax-function">useKeyWay</span>{`();\n\n`}<span className="syntax-keyword">await</span>{` `}<span className="syntax-variable">connection</span>.<span className="syntax-property">keyway</span>.<span className="syntax-function">sendPayment</span>{`({\n  `}<span className="syntax-property">invoice</span>{`,\n});`}</code></pre>
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
      <footer className="landing-footer"><Brand /><span>MIT licensed · Testnet prototype</span><span><a href="https://ckb-keyway-docs.vercel.app">Docs</a> · <a href="https://www.npmjs.com/package/@ckb-keyway/react">npm</a></span></footer>
    </main>
  );
}

function Brand() {
  return <div className="brand-lockup"><span className="brand-mark" aria-hidden="true">K</span><div><strong>CKB KeyWay</strong><span>Email-native Fiber wallet</span></div></div>;
}
