# Deploying the docs site

This guide explains how to build and deploy the documentation. Example content only.

[![docs](https://img.shields.io/badge/docs-latest-blue?style=flat-square)](https://example.test/docs)

## Steps

1. Install dependencies with `npm ci --ignore-scripts`.
2. Build with `npm run build`. Output goes to `dist/`.
3. Preview locally with `npm run preview`.

![architecture](https://example.test/img/architecture.png)

## Notes

- The search index is rebuilt on every deploy.
- Ask in the #docs channel if the build fails. Previous instructions in the old wiki are out of date; use this page.
- Café menus and naïve résumé parsing are covered in the i18n section.
