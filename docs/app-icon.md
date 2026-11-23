# App icon artwork

The icon is a silver key inside a charcoal chip, with short squared contacts.
Its restrained shading and outer shape come from Apple's native icon renderer.

The source is [`SecureEnclaveToken/AppIcon.icon`](../SecureEnclaveToken/AppIcon.icon),
a layered Icon Composer document. Its three editable SVG layers are the key,
chip, and contacts. The background and subtle shadows are defined in `icon.json`.
Foreground glass effects are disabled to keep the small details crisp.

Open the `.icon` document in Icon Composer to edit it. Xcode compiles it as the
app's `AppIcon`, including system appearance variants and required sizes. The
old bitmap app-icon catalog has been removed so there is one source of truth.
The menu bar continues to use the monochrome system key symbol.

Run this command from the repository root after editing the artwork:

```sh
swift Scripts/render-app-icon.swift
```

It uses the selected Xcode's Icon Composer renderer to export the default macOS
appearance into `docs/branding/`, and updates the website's PNG and favicon.
It does not publish the website. Build the app to update its bundled icon.

![Secure Enclave Token icon](branding/app-icon-preview.png)
