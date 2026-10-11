"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { LogoMark, MenuIcon, CloseIcon } from "./icons";
import { DOCS_URL, QUICKSTART_URL } from "./links";

const NAV = [
  { label: "Product", href: "/#product" },
  { label: "Developers", href: "/#developers" },
  { label: "Security", href: "/#security" },
  { label: "Docs", href: DOCS_URL },
];

export function SiteHeader({ bordered = false, current }: { bordered?: boolean; current?: "dashboard" }) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    document.body.classList.add("menu-open");
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    const onResize = () => { if (window.innerWidth > 900) setOpen(false); };
    window.addEventListener("keydown", onKey);
    window.addEventListener("resize", onResize);
    return () => {
      document.body.classList.remove("menu-open");
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", onResize);
    };
  }, [open]);

  const close = () => setOpen(false);
  return (
    <header className={`site-header${bordered ? " site-header--bordered" : ""}`}>
      <div className="site-header__inner">
        <Link href="/" className="brand" onClick={close}>
          <LogoMark label="CKB KeyWay home" />
          <span>CKB KeyWay</span>
        </Link>
        <nav aria-label="Main" className="site-nav">
          {NAV.map((item) => <a key={item.label} href={item.href}>{item.label}</a>)}
        </nav>
        <div className="site-header__actions">
          <Link href="/dashboard" className="site-header__dashboard" aria-current={current === "dashboard" ? "page" : undefined}>Dashboard</Link>
          <a href={QUICKSTART_URL} className="site-header__cta">Get started</a>
          <button
            type="button"
            className="menu-button"
            aria-label={open ? "Close menu" : "Open menu"}
            aria-expanded={open}
            aria-controls="mobile-menu"
            onClick={() => setOpen((value) => !value)}
          >
            {open ? <CloseIcon size={22} /> : <MenuIcon size={22} />}
          </button>
        </div>
      </div>
      <nav id="mobile-menu" aria-label="Mobile" className="mobile-menu" data-open={open}>
        {NAV.map((item) => <a key={item.label} className="mobile-menu__link" href={item.href} onClick={close}>{item.label}</a>)}
        <div className="mobile-menu__actions">
          <Link href="/dashboard" className="mobile-menu__secondary" onClick={close}>Dashboard</Link>
          <a href={QUICKSTART_URL} className="mobile-menu__primary" onClick={close}>Get started</a>
        </div>
      </nav>
    </header>
  );
}
