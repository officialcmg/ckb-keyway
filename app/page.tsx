import Link from "next/link";
import { CopyButton } from "./_components/copy-button";
import { SiteHeader } from "./_components/site-header";
import { CheckIcon, ChevronRight, CopyIcon, LogoMark } from "./_components/icons";
import { DOCS_URL, FIBER_DOCS_URL, GITHUB_URL, NPM_URL, QUICKSTART_URL, REACT_SDK_URL, SECURITY_MODEL_URL } from "./_components/links";
import "./landing.css";

const LANDING_CODE = `import {
  KeyWayProvider, useKeyWay, useCkbWallet, useFiber,
} from "@ckb-keyway/react";

export function Providers({ children }) {
  return (
    <KeyWayProvider appId="keyway_8fK2mQ7xL1pVn4sR9tYc0bWd">
      {children}
    </KeyWayProvider>
  );
}

export function Checkout({ invoice }) {
  const { authenticated, login } = useKeyWay();
  const { balance } = useCkbWallet();
  const fiber = useFiber();

  if (!authenticated) return <button onClick={login}>Sign in</button>;
  return <button onClick={() => fiber.payInvoice(invoice)}>Pay</button>;
}`;

const HOOKS = [
  ["useKeyWay", "Sign in, sign out and session state."],
  ["useCkbWallet", "Address, balance and a CCC signer, without starting Fiber."],
  ["useFiber", "Connect, open channels, create and pay invoices."],
] as const;

const BUILT_IN = [
  "The CKB signing key lives in Lit's secure hardware and is never exported to your app.",
  "Users approve every transaction before it's signed, and can require an emailed code for large transfers.",
  "Fiber keys and node backups are encrypted at rest.",
  "Each app has its own users, sessions and one-time codes.",
];

const GOOD_TO_KNOW = [
  "KeyWay's backend authorizes signing, and approvals appear inside your app's page. Lit doesn't yet verify the user on its own.",
  "Managed nodes run on KeyWay's infrastructure, which holds their fiber keys.",
  "Access to a user's inbox can recover their account until 2FA ships.",
  "KeyWay runs on CKB testnet and has not been audited yet.",
];

const STACK: Array<{ title: string; body: string; mono?: boolean }> = [
  { title: "Email code", body: "A six-digit code, isolated per app." },
  { title: "KeyWay account", body: "One permanent account per user, per app." },
  { title: "Signing key in Lit", body: "A secp256k1 key held in Lit's secure hardware." },
  { title: "CKB address", body: "ckt1qzda0cr0…5kqg5uk4g", mono: true },
  { title: "Fiber node", body: "Managed or in the browser, started when you call connect()." },
];

export default function Home() {
  return (
    <div className="lp">
      <SiteHeader />

      <section className="lp-hero">
        <div className="lp-hero__inner">
          <div className="lp-hero__copy">
            <a className="lp-pill" href={FIBER_DOCS_URL}>
              <span className="lp-pill__tag">New</span>
              <span>Fiber payments are live on CKB testnet</span>
              <ChevronRight size={14} />
            </a>
            <h1 className="lp-hero__title">Onboard anyone to CKB with an email address.</h1>
            <p className="lp-hero__lede">Give every user a CKB account the moment they sign in with email. No seed phrases or extensions, and Fiber payments built in.</p>
            <div className="lp-actions">
              <a className="btn btn--route btn--lg" href={QUICKSTART_URL}>Get started</a>
              <a className="btn btn--outline btn--lg" href={DOCS_URL}>Read the docs</a>
            </div>
            <p className="lp-hero__note">Open source under MIT. React SDK on npm.</p>
          </div>
          <HeroShot />
        </div>
      </section>

      <section id="product" className="lp-section lp-section--ruled">
        <div className="lp-stack">
          <div className="lp-heading">
            <p className="eyebrow lp-eyebrow">For your users</p>
            <h2 className="lp-h2">From sign-in to first payment, without leaving your app.</h2>
          </div>
          <div className="lp-moments">
            <figure className="lp-moment">
              <div className="lp-moment__card lp-moment__card--signin">
                <span className="lp-moment__title">Sign in to Acme Pay</span>
                <span className="lp-muted-14">Use your email to continue.</span>
                <span className="lp-moment__field">Email<span className="lp-moment__input">ana@acmepay.xyz</span></span>
                <span className="lp-moment__button">Continue with email</span>
              </div>
              <figcaption><span>They sign in with email</span><span>A one-time code, sent under your app&apos;s name. No passwords to store.</span></figcaption>
            </figure>
            <figure className="lp-moment">
              <div className="lp-moment__card lp-moment__card--account">
                <span className="lp-moment__row"><span className="lp-muted-14">Your CKB account</span><span className="status status--success"><span className="status__dot" />Ready</span></span>
                <span className="lp-moment__balance">1,250.00 <span>CKB</span></span>
                <span className="lp-moment__address"><span>ckt1qzda0cr0…5kqg5uk4g</span><CopyIcon className="lp-moment__copy" /></span>
                <span className="lp-moment__foot">The same address on every device they sign in from.</span>
              </div>
              <figcaption><span>Their account is ready</span><span>A real CKB address, recovered by email. Nothing to install or write down.</span></figcaption>
            </figure>
            <figure className="lp-moment">
              <div className="lp-moment__card lp-moment__card--sent">
                <span className="lp-moment__check"><CheckIcon size={22} /></span>
                <span className="lp-moment__sent">Payment sent</span>
                <span className="lp-moment__to">4.50 CKB to Bottle Coffee</span>
                <span className="lp-moment__meta"><span>Network</span><span>Fiber, CKB testnet</span><span>Fee</span><span>0.001 CKB</span></span>
              </div>
              <figcaption><span>They pay over the Fiber Network</span><span>Low-fee CKB payments through payment channels. The SDK opens the channel and pays the invoice, with no browser extension.</span></figcaption>
            </figure>
          </div>
        </div>
      </section>

      <section id="developers" className="lp-section lp-section--ruled">
        <div className="lp-split lp-split--dev">
          <div className="lp-split__copy lp-split__copy--dev">
            <p className="eyebrow lp-eyebrow">For your team</p>
            <h2 className="lp-h2">Three hooks. That&apos;s the integration.</h2>
            <p className="lp-lede lp-lede--narrow">Wrap your app in one provider, register your domains in the dashboard, and use the hooks wherever you need them.</p>
            <dl className="lp-hooks">
              {HOOKS.map(([name, body]) => <div key={name}><dt>{name}</dt><dd>{body}</dd></div>)}
            </dl>
            <a className="link lp-link" href={QUICKSTART_URL}>Read the quickstart</a>
          </div>
          <figure className="code-panel lp-code">
            <figcaption className="lp-code__bar"><span>app/wallet.tsx</span><CopyButton value={LANDING_CODE} label="Copy code" className="icon-button lp-code__copy" /></figcaption>
            <pre><code><span className="tk-k">import</span>{" {\n  KeyWayProvider, useKeyWay, useCkbWallet, useFiber,\n} "}<span className="tk-k">from</span> <span className="tk-s">&quot;@ckb-keyway/react&quot;</span>;{"\n\n"}<span className="tk-k">export function</span>{" Providers({ children }) {\n  "}<span className="tk-k">return</span>{" (\n    <"}<span className="tk-c">KeyWayProvider</span> appId=<span className="tk-s">&quot;keyway_8fK2mQ7xL1pVn4sR9tYc0bWd&quot;</span>{">\n      {children}\n    </"}<span className="tk-c">KeyWayProvider</span>{">\n  );\n}\n\n"}<span className="tk-k">export function</span>{" Checkout({ invoice }) {\n  "}<span className="tk-k">const</span>{" { authenticated, login } = useKeyWay();\n  "}<span className="tk-k">const</span>{" { balance } = useCkbWallet();\n  "}<span className="tk-k">const</span>{" fiber = useFiber();\n\n  "}<span className="tk-k">if</span>{" (!authenticated) "}<span className="tk-k">return</span>{" <"}<span className="tk-c">button</span>{" onClick={login}>Sign in</"}<span className="tk-c">button</span>{">;\n  "}<span className="tk-k">return</span>{" <"}<span className="tk-c">button</span>{" onClick={() => fiber.payInvoice(invoice)}>Pay</"}<span className="tk-c">button</span>{">;\n}"}</code></pre>
          </figure>
        </div>
      </section>

      <section className="lp-section lp-section--ruled">
        <div className="lp-stack lp-stack--tight">
          <div className="lp-heading">
            <h2 className="lp-h2">Run Fiber your way.</h2>
            <p className="lp-lede">Every user gets their own Fiber node. Choose where it runs with one provider prop.</p>
          </div>
          <div className="lp-modes">
            <article className="lp-mode lp-mode--default">
              <span className="lp-mode__head"><span className="lp-mode__title">Managed node</span><span className="lp-mode__tag">Default</span></span>
              <p>KeyWay runs a dedicated Fiber node for each user. It stays online, so payments can arrive while the app is closed.</p>
              <ul><li>Nothing runs in the user&apos;s browser</li><li>Encrypted node backups</li><li>KeyWay&apos;s host holds the node key</li></ul>
              <code>nodeMode=&quot;managed&quot;</code>
            </article>
            <article className="lp-mode">
              <span className="lp-mode__title">In-browser node</span>
              <p>The node runs inside the user&apos;s tab with WebAssembly. Channel state stays on their device.</p>
              <ul><li>No node on our servers</li><li>Moves devices through an encrypted sign-out handoff</li><li>Online only while the tab is open</li></ul>
              <code>nodeMode=&quot;browser&quot;</code>
            </article>
          </div>
        </div>
      </section>

      <section id="security" className="lp-section lp-section--ruled lp-security">
        <div className="lp-split lp-split--security">
          <div className="lp-split__copy lp-split__copy--security">
            <p className="eyebrow lp-eyebrow">Security model</p>
            <h2 className="lp-h2">What protects your users, and what to know.</h2>
            <p className="lp-lede">We publish exactly where keys live and who can act on them, including the limits of an early release.</p>
            <a className="link lp-link" href={SECURITY_MODEL_URL}>Read the full security model</a>
          </div>
          <div className="lp-facts">
            <div className="lp-facts__col"><h3>Built in</h3>{BUILT_IN.map((fact) => <p key={fact}>{fact}</p>)}</div>
            <div className="lp-facts__col"><h3>Good to know</h3>{GOOD_TO_KNOW.map((fact) => <p key={fact}>{fact}</p>)}</div>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-split lp-split--stack">
          <div className="lp-split__copy lp-split__copy--stack">
            <p className="eyebrow lp-eyebrow">Under the hood</p>
            <h2 className="lp-h2">Standard CKB, end to end.</h2>
            <p className="lp-lede lp-lede--narrow">KeyWay accounts are standard CKB lock scripts built with CCC: secp256k1, or Omnilock once a user turns on recovery. Inspect them in the CKB explorer like any other address, and pay any Fiber invoice on the network.</p>
          </div>
          <ol className="lp-route">
            {STACK.map((stop) => (
              <li key={stop.title}>
                <span className="lp-route__rail"><span className="lp-route__stop" /><span className="lp-route__line" /></span>
                <span className="lp-route__text"><span className="lp-route__title">{stop.title}</span><span className={stop.mono ? "lp-route__mono" : "lp-route__body"}>{stop.body}</span></span>
              </li>
            ))}
            <li>
              <span className="lp-route__rail"><span className="lp-route__end" /></span>
              <span><span className="lp-route__title">Payment</span><span className="lp-route__body">Routed over Fiber to any invoice on the network.</span></span>
            </li>
          </ol>
        </div>
      </section>

      <section className="lp-section lp-section--ruled">
        <div className="lp-stack lp-stack--tight">
          <h2 className="lp-h2">Roadmap</h2>
          <div className="lp-roadmap">
            <div className="lp-roadmap__col lp-roadmap__col--now"><span className="lp-roadmap__title"><span className="lp-roadmap__dot" />Now on testnet</span><ul><li>Email sign-in with per-app isolation</li><li>CKB accounts and balances</li><li>Fiber channels and payments</li><li>Managed and in-browser nodes</li><li>Developer dashboard</li></ul></div>
            <div className="lp-roadmap__col lp-roadmap__col--next"><span className="lp-roadmap__title">Next</span><ul><li>User verification enforced inside Lit</li><li>A second recovery factor</li><li>Independent security review</li></ul></div>
            <div className="lp-roadmap__col"><span className="lp-roadmap__title">Exploring</span><ul><li>Mainnet support</li><li>Inbound liquidity for new channels</li><li>Fiber keys the backend never sees</li></ul></div>
          </div>
        </div>
      </section>

      <section className="lp-section lp-section--cta">
        <div className="lp-cta">
          <div className="lp-cta__copy">
            <h2>Start building on CKB testnet.</h2>
            <p>Register an app, add your domains and ship email sign-in today.</p>
          </div>
          <div className="lp-actions lp-actions--cta">
            <a className="btn btn--lg lp-cta__primary" href={QUICKSTART_URL}>Get started</a>
            <Link className="btn btn--lg lp-cta__secondary" href="/app">Try the demo</Link>
          </div>
        </div>
      </section>

      <footer className="lp-footer">
        <div className="lp-footer__inner">
          <div className="lp-footer__top">
            <div className="lp-footer__brand">
              <span className="lp-footer__lockup"><LogoMark size={24} /><span>CKB KeyWay</span></span>
              <span className="lp-footer__tagline">Embedded wallets and Fiber payments for apps on CKB.</span>
            </div>
            <nav aria-label="Footer" className="lp-footer__nav">
              <div><span>Product</span><Link href="/app">Live demo</Link><Link href="/dashboard">Dashboard</Link><a href="#security">Security</a></div>
              <div><span>Developers</span><a href={DOCS_URL}>Docs</a><a href={QUICKSTART_URL}>Quickstart</a><a href={REACT_SDK_URL}>React SDK</a></div>
              <div><span>Project</span><a href={GITHUB_URL}>GitHub</a><a href={NPM_URL}>npm</a></div>
            </nav>
          </div>
          <div className="lp-footer__legal"><span>© 2026 CKB KeyWay. Released under the MIT license.</span><span>CKB testnet. Test CKB has no value.</span></div>
        </div>
      </footer>
    </div>
  );
}

/** Product shot: a fictional customer app with KeyWay sign-in. */
function HeroShot() {
  return (
    <div className="lp-shot" role="img" aria-label="Product preview: Acme Pay with KeyWay sign-in">
      <div className="lp-shot__wallet">
        <div className="lp-shot__bar">
          <span className="lp-shot__logo" />
          <span className="lp-shot__name">Acme Pay</span>
          <span className="lp-shot__addr">ckt1qzda…uk4g</span>
        </div>
        <div className="lp-shot__balance">
          <span className="lp-shot__label">Balance</span>
          <span className="lp-shot__amount">1,250.00 <span>CKB</span></span>
          <span className="lp-shot__buttons"><span className="lp-shot__send">Send</span><span className="lp-shot__receive">Receive</span></span>
        </div>
        <div className="lp-shot__activity">
          <div><span className="lp-shot__dot lp-shot__dot--in" /><span className="lp-shot__what">Received over Fiber</span><span className="lp-shot__amt">+1.00</span><span className="lp-shot__when">2 min</span></div>
          <div><span className="lp-shot__dot lp-shot__dot--out" /><span className="lp-shot__what">Paid Bottle Coffee</span><span className="lp-shot__amt">−4.50</span><span className="lp-shot__when">1 h</span></div>
        </div>
      </div>
      <div className="lp-shot__modal">
        <span className="lp-shot__modal-head"><span className="lp-shot__modal-title">Sign in to Acme Pay</span><span className="lp-shot__modal-sub">Enter the code we sent to ana@acmepay.xyz</span></span>
        <span className="lp-shot__otp">
          {["4", "8", "1", "0", "2", ""].map((digit, index) => <span key={index} className={index === 4 ? "is-active" : undefined}>{digit}</span>)}
        </span>
        <span className="lp-shot__continue">Continue</span>
        <span className="lp-shot__secured"><LogoMark size={12} color="#4A5370" />Secured by CKB KeyWay</span>
      </div>
    </div>
  );
}
