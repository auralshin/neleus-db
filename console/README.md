# neleus-db console

React + Vite web console. `neleus-db serve` embeds the built `console/dist`
and serves it at `/`.

```bash
npm --prefix console ci
npm --prefix console run build   # writes console/dist; then cargo build embeds it
```

Without `console/dist`, the build warns and `/` serves a "not bundled" note.
`cargo build --no-default-features` skips the console entirely.

Development with hot reload:

```bash
neleus-db --db ./db serve --cors-origin http://localhost:5173
npm --prefix console run dev
```

The dev console asks for the server URL (default `http://127.0.0.1:7117`) and
a token, stored in `localStorage`. `npm run lint` runs ESLint.

Server and routes: [docs/http-api.md](../docs/http-api.md).
