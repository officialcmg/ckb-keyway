import Link from "next/link";
import { DeveloperDashboard } from "./dashboard-client";

export default function DashboardPage() {
  return (
    <main className="dashboard-frame">
      <header className="site-header">
        <Link className="brand-lockup brand-link" href="/">
          <span className="brand-mark" aria-hidden="true">K</span>
          <div><strong>CKB KeyWay</strong><span>Developer console</span></div>
        </Link>
        <div className="app-links"><a href="https://ckb-keyway-docs.vercel.app">Docs</a><Link href="/app">Wallet demo</Link></div>
      </header>
      <DeveloperDashboard />
    </main>
  );
}
