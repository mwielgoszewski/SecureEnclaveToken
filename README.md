# SecureEnclaveToken Overview

SecureEnclaveToken allows you to generate and use credentials backed by
a cryptographic key stored on the Secure Enclave, protected with your
fingerprint. SecureEnclaveToken provides a user interface for generating
and deleting keys, creating certificate signing requests, and
associating certificates with keys to establish an identity. This
identity (comprised of key and certificate) can be used like that of an
identity on a smartcard; e.g., authentication, establishing secured
communication channels, etc.

## Building

1. Open .xcodeproj in Xcode
2. For each target under "Signing & Capabilities", configure the Team
   used for signing the application.
3. Run the application

If you wish to build an installable version of the application, in the
menu select Product > Archive.

## Steps to creating an identity

1. Launch SecureEnclaveToken.app.
2. Generate a key. Choose your key access control and security
   requirements.
3. Generate a certificate signing request. Use the text fields
   (Common Name, Email Address, etc) to specify attributes.
4. Submit your saved certificate request to your certificate authority,
   retrieve signed certificate and convert it to DER format with `.cer`
   extension.
5. Import signed certificate. On first use, you'll see a button that
   says "Query Token Configuration". If no certificate is currently
   loaded, you'll be prompted with an open file panel to select a
   certificate.

Once you have a key generated and a signed certificate imported, the UI
should indicate you have 2 token keychain items loaded.

![SecureEnclaveToken](https://github.com/mwielgoszewski/SecureEnclaveToken/blob/main/images/SecureEnclaveToken.png)

## Debugging

To view the identities loaded in SecureEnclaveTokenExtension, run

    system_profiler SPSmartCardsDataType

To list identites in your ctkd-db:

    defaults read ~/Library/Preferences/com.apple.security.ctkd-db

Enable verbose logging for smartcard extensions (logs can be viewed in
Console.app, under the SecureEnclaveTokenExtension process):

    sudo defaults write /Library/Preferences/com.apple.security.smartcard Logging 1


## References

* [Gate](https://bitbucket.org/twocanoes/gate-secure-enclave-token-management)

  I happened to come across this late in my research, helped establish
  some patterns for working with the TKTokenConfiguration classes, of
  which documentation may as well have been non-existent. Similar
  CryptoTokenKit app extension, written in Objectivc-C.

* [CertificateSigningRequest](https://github.com/cbaker6/CertificateSigningRequest)

  Swift package for generating certificate signing requests, written by
  Corey Baker. Components ported from [ios-csr](https://github.com/ateska/ios-csr)
  written by Ales Teska.
