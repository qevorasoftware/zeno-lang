# Vendored UI assets

These files come from the Qevora AI SaaS UI kit
(https://github.com/qevorasoftware/qevora-ai-saas-ui, MIT licence) so the admin
console renders with the house design and **without any CDN dependency** —
third-party hosts are blocked in exactly the places an owner consoles from.

- `css/bootstrap.min.css`, `js/bootstrap.bundle.min.js` — Bootstrap 5.3 (MIT)
- `icons/` — Bootstrap Icons (MIT, font subset as shipped by the kit)
- `fonts/inter/` — Inter (SIL OFL 1.1)
- `css/style.css`, `css/components.css`, `css/dark.css`, `css/fonts.css`,
  `js/theme.js`, `js/app.js`, `js/sidebar.js` — the Qevora theme layer (MIT)
- `js/chart.umd.js` — Chart.js 4 (MIT)

Everything else in `zeno/web/` is this project's own.
