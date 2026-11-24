# Signed releases

The normal release process is **GitHub builds and tests → your Mac signs and
notarizes → you publish the signed ZIP on GitHub Releases**. Apple signing and
notarization credentials stay in your local Keychain. The build workflow needs
no Apple secrets.

## Prepare the version and CI build

For this release, use **version 3.0, build 2**, with the GitHub tag **`v3.0`**.
The existing `v2.0` release is from 2022 and points to different source; leave it
intact. The earlier notarized test artifact still identifies itself as 2.0,
build 1, so rebuild before publishing 3.0.

1. Set `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` for both the app and
   extension, in Debug and Release. Both Info.plists reference those settings.
   Increment the build number for a replacement build of the same release.
2. Commit and push the version, release tooling, and documentation. Wait for
   **Actions → Build and test** to succeed on that exact commit.
3. Record the run URL and full source commit SHA for the release notes and tag.
   Download `SecureEnclaveToken-unsigned-arm64` from that run.
4. Extract the Actions download, then the inner
   `SecureEnclaveToken-unsigned-arm64.zip`. Use a fresh folder so an older
   `SecureEnclaveToken.app` in Downloads is not mistaken for the new build.

The unsigned CI app may show “damaged and can’t be opened” when launched from a
browser download. It has linker-generated ad hoc signatures, not a complete
Developer ID bundle signature. Proceed to local signing instead of launching it
or removing quarantine as a substitute for signing.

## Set up local credentials once

Use Xcode command-line tools and Python 3.9 or later. Run the locally reviewed
[signing helper](../Scripts/sign-local.py) and entitlement templates from this
checkout; do not execute a helper shipped inside an artifact.

### Developer ID Application identity

```sh
security find-identity -v -p codesigning
```

Choose **Developer ID Application**, and copy its 40-character SHA-1 fingerprint.
An **Apple Development**, **Apple Distribution**, or **Developer ID Installer**
identity is not the certificate used by this ZIP release process. The identity
must include its matching private key in your Mac's Keychain. You do not need to
export a `.p12` or place Apple credentials in GitHub.

If needed, create a Developer ID Application certificate in Xcode's **Settings →
Accounts → Manage Certificates**, or through the Apple Developer portal. Creating
this locally managed certificate requires the team's **Account Holder**. If
Xcode says the operation can only be performed by the Account Holder, verify the
selected account and team on the Developer website and try the portal there.

If another person holds that role, generate a CSR on your signing Mac in
**Keychain Access → Certificate Assistant → Request a Certificate From a
Certificate Authority**, choosing **Saved to disk**. Send only the CSR to the
Account Holder. They create the Developer ID Application certificate with it;
install the returned `.cer` on the same Mac. The private key remains on your Mac.

“Not in Keychain” is not fixed by downloading a certificate alone if its private
key is missing. Import the certificate and key from another Mac you control, or
create a new identity. Identical fingerprints listed twice refer to the same
certificate; do not revoke it just to clean up the display.

### Provisioning profiles that authorize that exact certificate

In [Certificates, Identifiers & Profiles](https://developer.apple.com/account/),
create two **Developer ID** distribution provisioning profiles, selecting your
signing certificate and these macOS App IDs:

- `com.mwielgoszewski.SecureEnclaveToken`
- `com.mwielgoszewski.SecureEnclaveToken.SecureEnclaveTokenExtension`

Both must authorize `PREFIX.com.mwielgoszewski.SecureEnclaveToken` as a keychain
access group. Preserve the existing team and App ID prefix so installed keys
remain accessible. This project uses team `W8LYJ3542D`.

A profile authorizes specific certificates, not every certificate with the same
name or team. The earlier `XC_OSX_…` profiles authorized an older Developer ID
certificate and had to be replaced. After replacing a signing certificate,
regenerate **both** profiles with the new certificate selected. Xcode-managed
profiles may not appear in the portal; create named replacements if needed.

The commands below use the filenames from the successful local signing run:

- `~/Downloads/SecureEnclaveToken.provisionprofile`
- `~/Downloads/SecureEnclaveTokenSecureEnclaveTokenExtension.provisionprofile`

Adjust the paths if you store them elsewhere. The helper checks expiry, team,
App IDs, the authorized certificate fingerprint, and the shared access group
before signing. Development and Mac App Store profiles are not substitutes.

### Notarization credentials

Store credentials in your **local login Keychain**, once:

```sh
xcrun notarytool store-credentials setoken-notary \
  --apple-id 'YOUR_APPLE_ID' \
  --team-id W8LYJ3542D \
  --keychain "$HOME/Library/Keychains/login.keychain-db"
```

Enter an **app-specific password** at the secure prompt, not your regular Apple
Account password. Create it at [account.apple.com](https://account.apple.com/)
under **Sign-In and Security → App-Specific Passwords**. A `401` means credential
validation failed; verify the Apple ID, team, and app-specific password and retry.
Once it reports “Credentials saved to Keychain”, reuse `setoken-notary` for later
releases; do not repeat setup on every build.

Alternatively, `store-credentials` accepts an existing App Store Connect API key
via `--key`, `--key-id`, and (for team keys) `--issuer`. Neither approach requires
credentials in GitHub or in a shell script. A continuation backslash must be the
last character on a shell command line, with no trailing spaces.

## Sign a downloaded CI build on your Mac

From the repository root, inspect the extracted app. Substitute its actual path
if you used a separate download folder:

```sh
python3 -B Scripts/sign-local.py \
  --app "$HOME/Downloads/SecureEnclaveToken.app" --check

/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
  "$HOME/Downloads/SecureEnclaveToken.app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
  "$HOME/Downloads/SecureEnclaveToken.app/Contents/Info.plist"
```

For this release, the last two commands must print **3.0** and **2**. Check the
extension's `Contents/Info.plist` under
`Contents/PlugIns/SecureEnclaveTokenExtension.appex` as well.

`--check` validates the two-executable bundle layout and prints binary hashes;
it does **not** verify the GitHub run or prove the binaries match source. Select
an artifact from a reviewed commit and trusted run. If independence from CI's
build integrity is required, build the reviewed source locally.

Sign with the fingerprint returned by `security find-identity`:

```sh
python3 -B Scripts/sign-local.py \
  --app "$HOME/Downloads/SecureEnclaveToken.app" \
  --identity YOUR_40_CHARACTER_DEVELOPER_ID_FINGERPRINT \
  --team W8LYJ3542D \
  --app-profile "$HOME/Downloads/SecureEnclaveToken.provisionprofile" \
  --extension-profile "$HOME/Downloads/SecureEnclaveTokenSecureEnclaveTokenExtension.provisionprofile" \
  --notary-profile setoken-notary \
  --output build/local-release-3.0
```

The output directory must be new. This preserves the successful earlier test
under `build/local-release`. For another attempt, choose a different output path.
The original downloaded app is left untouched.

The helper embeds the profiles and uses the checkout's entitlements, signing the
extension before the app with hardened runtime and secure timestamps. It verifies
the signatures, submits to Apple, requires **Accepted**, staples and validates the
ticket, and checks Gatekeeper before producing:

- `build/local-release-3.0/SecureEnclaveToken-signed-arm64.zip`
- `build/local-release-3.0/SecureEnclaveToken-signed-arm64.zip.sha256`

It does not run the app, installer, or other artifact scripts, and does not upload
the result to GitHub. Inspect `notarization-log.json` for warnings even on success.
Failed submissions retain diagnostic files but do not produce the final ZIP.

### If signing or notarization stops

| Message | Next step |
| --- | --- |
| No matching valid Developer ID Application identity | Use a Developer ID Application fingerprint with its private key installed; an Apple Development identity cannot substitute. |
| Provisioning profile does not authorize the selected signing certificate | Regenerate both Developer ID profiles with the exact signing certificate selected, then use the newly downloaded files. |
| Output directory already exists | Pick a new `--output` directory; keep previous artifacts and logs until their status is understood. |
| Notarization credential `401` | Store a valid app-specific password for the correct Apple ID and team in the same Keychain profile. |
| Notarization wait times out | Apple's processing continues. Query the existing submission before submitting again. |

For a timeout, get the ID from `notarization.json`, then run:

```sh
xcrun notarytool info SUBMISSION_ID \
  --keychain-profile setoken-notary \
  --keychain "$HOME/Library/Keychains/login.keychain-db"
```

Use `wait` instead of `info` to wait for completion. If it later succeeds, staple
and validate the retained app, run `codesign --verify --deep --strict` and
`spctl --assess --type execute`, then repackage with
`ditto -c -k --sequesterRsrc --keepParent` and generate a new ZIP checksum.
Do not distribute the pre-stapling `notarization.zip`.

## Test and publish the release

1. Open the **signed copy** in `build/local-release-3.0`, not the original in
   Downloads. Verify that the extension loads, existing identities remain usable,
   and a real signing or client-authentication operation succeeds. Test Touch ID
   for the flows you intend to describe as verified. Notarization does not test
   Secure Enclave or CryptoTokenKit behavior.
2. Check the final ZIP checksum:

   ```sh
   (cd build/local-release-3.0 && shasum -a 256 -c SecureEnclaveToken-signed-arm64.zip.sha256)
   ```

3. Tag the **exact source commit from the successful CI run** as `v3.0`. Do not
   point the tag at a later commit or move the existing `v2.0` tag. For example,
   replace `SOURCE_COMMIT_SHA_FROM_CI` before running:

   ```sh
   git tag -a v3.0 SOURCE_COMMIT_SHA_FROM_CI -m 'SecureEnclaveToken 3.0'
   git push origin v3.0
   ```

4. In GitHub **Releases → Draft a new release**, select `v3.0` and title it
   **SecureEnclaveToken 3.0**. Attach only the final signed ZIP and its `.sha256`
   file. Add the build run URL and full source SHA to the release notes.
5. State prominently: **Apple Silicon only; macOS Tahoe 26 or later**. Describe
   the signed/notarized download, installation by unzipping and moving the app to
   Applications, and the updated app, CLI, SSH, and certificate workflows. Keep
   hardware-test claims limited to checks actually performed on this build.
6. Publish when the hardware checks pass. Download the published ZIP through a
   browser, confirm its checksum, and verify that it opens through Gatekeeper.
7. Verify these links before deploying the prepared website changes:

   - [Signed ZIP](https://github.com/mwielgoszewski/SecureEnclaveToken/releases/download/v3.0/SecureEnclaveToken-signed-arm64.zip)
   - [Release notes](https://github.com/mwielgoszewski/SecureEnclaveToken/releases/tag/v3.0)

The [website source](../website/README.md) links to the signed ZIP and release
notes, and displays the published ZIP checksum in its download FAQ. Update that
checksum whenever the downloadable file changes. If a separate `.sha256` asset
is uploaded, verify it too before linking to it. Keep website changes staged
until their release is public. Updating the app repository does not deploy the
separate Sites copy.

## Validation record

On November 23, 2026, the local helper successfully signed and notarized the
unsigned 2.0/build-1 artifact from Actions run `45257946444`. Apple accepted
submission `e483a028-d6c3-490c-bee4-2321a572d6db` with no issues. Stapling,
signature validation, and Gatekeeper assessment passed. This validates the local
release process; the new 3.0 build still needs its own signing run and hardware
checks. The optional hosted signing workflow below has not been validated end to
end with credentials.

Validation without credentials:

```sh
python3 -B Tests/CI/test_signing.py
python3 -B Tests/CI/test_sign_local.py
```

## Optional: sign on GitHub-hosted runners

The following alternative requires placing Apple credentials in GitHub. Skip it
when using local signing above.

The [Signed release workflow](../.github/workflows/release.yml) builds an ARM64
app on macOS 26, signs it for distribution outside the Mac App Store, notarizes
it, staples Apple's ticket, and uploads a ZIP with a SHA-256 checksum. It is
manually triggered on `main`, using the GitHub environment named `release`.
It does not create a GitHub Release or publish downloads automatically.

The regular build workflow continues to produce unsigned verification artifacts.
The release workflow rebuilds the checked-out source and runs the tests; it does
not sign an arbitrary ZIP downloaded from another workflow.

### Check what you already have

Run locally:

```sh
security find-identity -v -p codesigning
```

Look for **Developer ID Application: your name or company (TEAMID)**. A valid
identity includes the certificate and its matching private key. In Keychain
Access, select **My Certificates** and expand the certificate to see its key.
An **Apple Development** identity is for development, not public distribution.
A **Developer ID Installer** certificate is for installer packages; this ZIP
workflow needs **Developer ID Application** instead.

In [App Store Connect](https://appstoreconnect.apple.com/), open **Users and
Access → Integrations → App Store Connect API → Team Keys**. Check for an active
team key and retain its Key ID, Issuer ID, and downloaded `.p8` private key.
The portal does not let you download a private key again. If the file is lost,
create a replacement; do not revoke a key still used by other automation.
This workflow uses a team API key, not an individual API key.

### Create missing signing credentials

1. In Xcode **Settings → Accounts**, select the Apple Developer team, open
   **Manage Certificates**, and create a **Developer ID Application** certificate
   if your account has permission. The Account Holder can also create it through
   [Certificates, Identifiers & Profiles](https://developer.apple.com/account/).
   Use a locally generated certificate with an exportable private key for this
   workflow; cloud-managed certificates are a different signing setup.
2. In Keychain Access, export that certificate **and its private key** as a
   password-protected `.p12` file. A downloaded `.cer` alone is insufficient.
3. In the developer portal, create **Developer ID provisioning profiles** for
   both registered macOS App IDs:
   - `com.mwielgoszewski.SecureEnclaveToken`
   - `com.mwielgoszewski.SecureEnclaveToken.SecureEnclaveTokenExtension`
   Select the Developer ID Application certificate for both. Both profiles must
   authorize the shared `PREFIX.com.mwielgoszewski.SecureEnclaveToken` keychain
   access group. Download the two `.provisionprofile` files. Development and
   Mac App Store profiles are not substitutes.
4. If needed, have the Account Holder request App Store Connect API access.
   Create a team API key with a role permitted to submit notarizations (Developer
   or higher), and download its `.p8` file once. A paid Apple Developer membership
   and current agreements are required.

The provisioning profiles matter here because the app and extension claim a
shared keychain access group. Keep the existing team and App ID prefix when
updating installed copies, or existing keys may become inaccessible. The project
currently uses team `W8LYJ3542D`; confirm this is the team you intend to release as.

### Configure GitHub

In repository **Settings → Environments**, create `release`. Limit its deployment
branches to `main`; add a required reviewer if you want a release approval step.
Store the following as **environment secrets**, not repository files:

| Secret | Value |
| --- | --- |
| `DEVELOPER_ID_P12_BASE64` | Base64-encoded `.p12`, including the private key |
| `DEVELOPER_ID_P12_PASSWORD` | Password used when exporting the `.p12` |
| `APP_PROFILE_BASE64` | Base64-encoded app Developer ID profile |
| `EXTENSION_PROFILE_BASE64` | Base64-encoded extension Developer ID profile |
| `NOTARY_API_KEY_BASE64` | Base64-encoded team API `.p8` key |
| `NOTARY_KEY_ID` | Team API Key ID |
| `NOTARY_ISSUER_ID` | Team API Issuer ID |

Add the environment **variable** `APPLE_TEAM_ID` with your ten-character team ID.
For each file-based secret, copy its encoding directly to the clipboard on Mac:

```sh
base64 -i /path/to/file | pbcopy
```

Paste into the corresponding GitHub secret field. Base64 is only an encoding;
these values remain private credentials. Do not paste them into issues, chat,
workflow source, or logs. Clear the clipboard after configuring the secrets.

### Run and verify

After merging the workflow, open **Actions → Signed release → Run workflow** and
select `main`. The job:

1. Checks configuration and runs the Swift, launcher, and profile-validation tests.
2. Installs the signing identity into a temporary keychain and validates both
   profiles' team, expiry, identifiers, and shared access group.
3. Archives and exports through Xcode with manual Developer ID signing. The
   Release configuration accepts separate `SETOKEN_APP_PROFILE` and
   `SETOKEN_EXTENSION_PROFILE` overrides; ordinary local builds still use
   automatic development signing.
4. Checks both bundles for Developer ID signatures, hardened runtime, sandboxing,
   provisioning profiles, and shared keychain access. Debugger entitlements must
   be absent.
5. Submits to Apple's notary service with `notarytool`, checks for `Accepted`,
   staples and validates the ticket, and checks Gatekeeper acceptance.
6. Packages the stapled app and uploads `SecureEnclaveToken-signed-arm64` plus
   `release-logs`. Signing credentials and installed profiles are cleaned up
   even when a step fails. The archive and private credential directory are not
   uploaded.

The notary wait is bounded to 30 minutes. If it times out, Apple's processing
continues; consult the submission ID in the logs and query that submission before
starting another release. Failed or pending notarization does not produce the
signed release artifact. Inspect Apple's notary log for warnings even on success.

Before publishing the ZIP, download it onto a physical Apple Silicon Mac and
verify that the app opens through Gatekeeper, the extension loads, and an existing
identity remains usable. Hosted runners cannot validate Secure Enclave operations,
Touch ID, or browser mTLS integration. The first full signing/notarization run
requires the credentials above and must still be validated end to end.

## References

- [Apple: Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)
- [Apple: Certificate signing requests](https://developer.apple.com/help/account/certificates/create-a-certificate-signing-request/)
- [Apple: Editing provisioning profiles](https://developer.apple.com/help/account/provisioning-profiles/edit-download-or-delete-profiles/)
- [GitHub: Managing releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
- [Apple: Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)
- [Apple: App Store Connect API keys](https://developer.apple.com/help/app-store-connect/get-started/app-store-connect-api/)
- [Apple: Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
- [GitHub: Installing an Apple certificate on macOS runners](https://docs.github.com/en/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications)
