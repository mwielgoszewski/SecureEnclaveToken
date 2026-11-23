# setoken.dev website

A responsive, buildless product page for Secure Enclave Token. All fonts and
assets are local; no analytics or third-party scripts are loaded.

## Preview

From this directory:

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist
```

Open http://localhost:8080. The page includes keyboard-accessible screenshot and
integration tabs, screenshot enlargement, copyable examples, and FAQ disclosures.

## Hosting

Upload the contents of `dist/` to any static host. No Node.js installation,
package manager, framework build, or server runtime is needed for this page.
The `.openai/hosting.json` file identifies the separate private Sites preview.
The source in this directory is also kept in the main app repository.

The intended public domain is `setoken.dev`. It has not been purchased or
connected by this project. After purchasing it, connect it to your chosen host
and configure HTTPS. This matters because `.dev` domains require HTTPS in browsers.

The page links to the public GitHub source and build instructions, rather than
claiming a signed installer exists. Update those links when a signed release is
available. Refresh screenshots from `docs/images/` when the app UI changes.
