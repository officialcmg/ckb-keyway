# CKB KeyWay docs

The public developer documentation for `@ckb-keyway/react`, served at <https://docs.ckbkeyway.dev>.

It is a [Fumadocs](https://fumadocs.dev) site on Next.js, styled with the CKB KeyWay design system tokens.

## Edit a page

Pages are MDX files in `content/docs/`. The sidebar order and section headings are in `content/docs/meta.json`. A new page needs an entry there.

The MDX components are defined in `components/mdx.tsx`:

- `Info` and `Warning` callouts
- `Steps` and `Step title="…"`
- `Cards` and `Card title="…" href="…"`
- `Tabs` and `Tab`

For package-manager tabs, write one fenced block per manager with `tab="npm"`, `tab="pnpm"` and so on. Add a filename header to a code block with `title="app/layout.tsx"`.

## Local preview

```sh
cd docs-site
npm install
npm run dev
```

The preview runs at `http://localhost:3000`. Before you push, run `npm run build` and `npm run types:check`.

## Deployment

The Vercel project `ckb-keyway-docs` (team Wildcard Labs) is connected to this GitHub repository with Root Directory `docs-site`. Pushing to `main` deploys to production. Other branches get preview deployments.

`vercel.json` holds an ignore command that skips the build when a commit leaves `docs-site/` unchanged, so app-only pushes do not rebuild the docs.

## Layout

| Path | Purpose |
| --- | --- |
| `app/(docs)/` | Docs layout and page route, served from `/` |
| `app/api/search/route.ts` | Built-in search index |
| `app/llms.txt`, `app/llms-full.txt`, `app/llms.mdx/` | Plain-text and Markdown copies of the docs for AI tools |
| `app/og/docs/` | Generated social preview images |
| `app/global.css` | Design-system colours, fonts and code-block styling |
| `lib/shared.ts` | Site name, URLs and the GitHub source location |
| `lib/layout.shared.tsx` | Nav logo and header links |
| `lib/code-theme.ts` | Syntax-highlighting theme built from the design-system code tokens |
