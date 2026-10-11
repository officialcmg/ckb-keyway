import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { gitConfig } from './shared';

function Mark() {
  return (
    <svg width="22" height="22" viewBox="0 0 48 48" aria-hidden="true">
      <path
        fill="var(--keyway-logo)"
        d="M14 6H34A8 8 0 0 1 42 14V15L37.5 19.5L42 24V25L38.5 28.5L42 32V34A8 8 0 0 1 34 42H14A8 8 0 0 1 6 34V14A8 8 0 0 1 14 6Z"
      />
    </svg>
  );
}

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <span className="flex items-center gap-2">
          <Mark />
          <span className="font-bold tracking-tight">CKB KeyWay</span>
          <span className="rounded-md border border-fd-border px-1.5 text-xs font-semibold text-fd-muted-foreground">
            Docs
          </span>
        </span>
      ),
      url: '/',
    },
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
    links: [
      { text: 'Live demo', url: 'https://ckbkeyway.dev/app', external: true },
      { text: 'Dashboard', url: 'https://ckbkeyway.dev/dashboard', external: true },
      { type: 'button', text: 'Get an app ID', url: 'https://ckbkeyway.dev/dashboard', external: true },
    ],
  };
}
