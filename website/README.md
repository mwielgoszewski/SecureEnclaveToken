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
The `.openai/hosting.json` file identifies the separate Sites deployment.
The source in this directory is also kept in the main app repository.

The intended public domain is `setoken.dev`. It has not been purchased or
connected by this project. After purchasing it, connect it to your chosen host
and configure HTTPS. This matters because `.dev` domains require HTTPS in browsers.

## Release downloads

The prepared page links directly to the `v3.0` GitHub release assets:

- `SecureEnclaveToken-signed-arm64.zip`
- `SecureEnclaveToken-signed-arm64.zip.sha256`

Keep these website changes staged until the signed release is published. The
version-specific URLs deliberately do not use `releases/latest`, which currently
could send visitors to the older 2.0 release. After publishing `v3.0`, verify the
ZIP, checksum, and release-notes URLs before deploying `dist/` or synchronizing
the separate Sites deployment. Updating this repository alone does not deploy
the Sites copy.

For later versions, update the hero version, both download buttons, checksum
link, release-notes link, and FAQ release link in `dist/index.html` together.
Follow [the release guide](../docs/releasing.md). Refresh screenshots from
`docs/images/` when the app UI changes.
