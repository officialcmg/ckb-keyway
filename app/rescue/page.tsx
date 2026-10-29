import { SiteFooter } from "../_components/site-footer";
import { SiteHeader } from "../_components/site-header";
import { RescueView } from "./rescue-view";
import "./rescue.css";

export const metadata = {
  title: "Rescue · CKB KeyWay",
  description: "Move everything out of a KeyWay account with one of its recovery backups, using only a public CKB node.",
};

export default function RescuePage() {
  return (
    <div className="rescue-page">
      <SiteHeader bordered />
      <main className="rescue-main">
        <div className="rescue-wrap">
          <header className="rescue-intro">
            <p className="eyebrow">Account recovery</p>
            <h1>Rescue a KeyWay account</h1>
            <p className="rescue-intro__lede">
              If KeyWay or the app you signed in to is gone, one of your account&apos;s backups can move everything at your
              KeyWay address to a wallet you choose. This page talks only to a public CKB node and your backup: no KeyWay
              server, no email, no account.
            </p>
          </header>
          <RescueView />
          <section className="rescue-notes" aria-label="How this works">
            <h2>How this works</h2>
            <ul>
              <li>Your KeyWay address names your recovery list. The page reads the list and your balance from the chain.</li>
              <li>A backup on the list signs one transaction that sends your CKB and tokens to the address you enter. Nothing else can.</li>
              <li>The recovery list itself stays where it is, with the CKB it holds.</li>
              <li>
                The page is open source and runs in your browser.{" "}
                <a className="link" href="https://github.com/officialcmg/ckb-keyway/tree/main/src/rescue">Read or host the code</a>.
              </li>
            </ul>
          </section>
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}
