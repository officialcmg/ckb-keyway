import type { ReactNode } from "react";
import { SiteFooter } from "../_components/site-footer";
import { SiteHeader } from "../_components/site-header";
import { DashboardProvider } from "./session";
import "./dashboard.css";

export const metadata = { title: "Dashboard · CKB KeyWay" };

export default function DashboardLayout({ children }: { children: ReactNode }) {
  return (
    <div className="dash-page">
      <SiteHeader bordered current="dashboard" />
      <main className="dash-main">
        <div className="dash-wrap">
          <DashboardProvider>{children}</DashboardProvider>
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}
