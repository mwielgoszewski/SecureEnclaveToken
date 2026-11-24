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

The public website is [setoken.dev](https://setoken.dev), served by the existing
Sites deployment. Preserve its public audience and custom domain when updating.

## Release downloads

The page links directly to the published `v3.0` release and its
`SecureEnclaveToken-signed-arm64.zip` asset. The download FAQ displays the ZIP's
SHA-256 from GitHub release metadata; it does not depend on a separate checksum
asset being uploaded. Download buttons, release notes, requirements, and
installation instructions all refer to version 3.0.

For later releases, publish the signed ZIP first, then update the hero version,
both download buttons, release-notes link, FAQ release link, and displayed
checksum in `dist/index.html` together. Verify the published asset digest and
URLs before deploying. Use version-specific URLs so visitors get the release
described on the page.

The main app repository and Sites source repository both retain the website
source. Updating this repository alone does not deploy the Sites copy. Follow
[the release guide](../docs/releasing.md) and refresh screenshots from
`docs/images/` when the app UI changes.
