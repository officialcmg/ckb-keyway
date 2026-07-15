# CKB KeyWay docs

This directory is the standalone Mintlify documentation site for `@ckb-keyway/react`.

```sh
npm install -g mint
cd docs
mint dev
```

The exported Mintlify site is deployed independently at `https://ckb-keyway-docs.vercel.app`.

## Publish an update

```sh
mint validate
mint broken-links
mint a11y
mint export --output /tmp/ckb-keyway-docs.zip
unzip -oq /tmp/ckb-keyway-docs.zip -d /tmp/ckb-keyway-docs-export
cd /tmp/ckb-keyway-docs-export
vercel link --yes --project ckb-keyway-docs
vercel deploy --prod --yes
```
