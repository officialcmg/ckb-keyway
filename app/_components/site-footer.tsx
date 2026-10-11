import { DOCS_URL, GITHUB_URL } from "./links";

/** The compact footer used by the demo and the dashboard. */
export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="site-footer__inner">
        <span>© 2026 CKB KeyWay. Released under the MIT license.</span>
        <span className="site-footer__links"><a href={DOCS_URL}>Docs</a><a href={GITHUB_URL}>GitHub</a></span>
      </div>
    </footer>
  );
}
