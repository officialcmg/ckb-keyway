# CKB KeyWay docs

This directory contains the standalone developer documentation for `@ckb-keyway/react`.

The source is written in MDX and configured with Mintlify. We use the Mintlify CLI to preview, validate, and export the site, then deploy the generated static bundle as a separate Vercel project.

- Documentation: <https://ckb-keyway-docs.vercel.app>
- Demo application: <https://ckb-keyway.vercel.app>
- npm package: <https://www.npmjs.com/package/@ckb-keyway/react>

## Tooling

- Mintlify `mint` CLI for local preview, validation, link checks, accessibility checks, and static export
- MDX for documentation pages
- `docs.json` for navigation, theme, branding, and external links
- Vercel CLI for the independent production deployment

The MDX files and `docs.json` are the source of truth. Exported ZIP files and unpacked static assets are generated deployment artifacts and are not committed.

## Local preview

Install the CLIs once:

```sh
npm install -g mint
npm install -g vercel
```

Run the docs locally:

```sh
cd docs
mint dev
```

Mintlify serves the preview at `http://localhost:3000` by default.

## How the first deployment was created

1. We authored the public SDK pages and navigation in this directory.
2. We authenticated the Mintlify CLI with `mint login`.
3. We validated the build, links, and accessibility locally.
4. We used `mint export` because the CLI does not directly publish a hosted Mintlify project.
5. We unpacked the static export into a temporary directory.
6. We linked that directory to a separate Vercel project named `ckb-keyway-docs`.
7. We deployed it to production and received the stable `ckb-keyway-docs.vercel.app` alias.
8. We added the docs and npm links to the landing page and reference wallet, then deployed the main application separately.

First-time Vercel setup:

```sh
mint login
vercel login
mint export --output /tmp/ckb-keyway-docs.zip
mkdir -p /tmp/ckb-keyway-docs-export
unzip -oq /tmp/ckb-keyway-docs.zip -d /tmp/ckb-keyway-docs-export
cd /tmp/ckb-keyway-docs-export
vercel link --yes --project ckb-keyway-docs
vercel deploy --prod --yes
```

## Publish an update

Run these commands from this `docs` directory:

```sh
mint validate
mint broken-links
mint a11y
mint export --output /tmp/ckb-keyway-docs.zip
unzip -oq /tmp/ckb-keyway-docs.zip -d /tmp/ckb-keyway-docs-export
cd /tmp/ckb-keyway-docs-export
vercel deploy --prod --yes
```

If the temporary export directory no longer contains its Vercel project link, run this before deploying:

```sh
vercel link --yes --project ckb-keyway-docs
```

After deployment, verify the overview, quickstart, Fiber payments, and React SDK pages return HTTP 200 and render without browser console errors.
