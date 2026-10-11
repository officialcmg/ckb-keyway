import { RootProvider } from 'fumadocs-ui/provider/next';
import type { Metadata } from 'next';
import { Albert_Sans, IBM_Plex_Mono } from 'next/font/google';
import { appName, siteUrl } from '@/lib/shared';
import './global.css';

const sans = Albert_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700', '800'],
  variable: '--font-keyway-sans',
});

const mono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500'],
  variable: '--font-keyway-mono',
});

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: { default: `${appName} docs`, template: `%s · ${appName} docs` },
  description: 'Documentation for the CKB KeyWay React SDK: email sign-in, CKB accounts and Fiber payments.',
  icons: { icon: '/favicon.svg' },
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <body className="flex flex-col min-h-screen">
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
