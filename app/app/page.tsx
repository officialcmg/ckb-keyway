import { AuthPanel } from "../auth-panel";
import { SiteFooter } from "../_components/site-footer";
import { SiteHeader } from "../_components/site-header";
import "./demo.css";

export const metadata = { title: "Live demo · CKB KeyWay" };

export default async function DemoPage({ searchParams }: { searchParams: Promise<{ mode?: string; screen?: string }> }) {
  const params = await searchParams;
  const nodeMode = params.mode === "browser" ? "browser" : "managed";
  const devScreen = process.env.NODE_ENV !== "production" ? params.screen : undefined;
  return (
    <div className="demo-page">
      <SiteHeader bordered />
      <main className="demo-main">
        <div className="demo-wrap">
          <AuthPanel nodeMode={nodeMode} devScreen={devScreen} />
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}
