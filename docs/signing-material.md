# Signing material

Apple signing material lives in Skarbiec and is read by the programs that sign:
Stado reads it while it builds a release, and a repository's GitHub Actions
workflow reads the copies a tool publishes to it. Each value is one field of a
vault item; the item and field every release reads are the coordinates its
release manifest declares in `secret_env` (`.wisent-release.json`), so this page
names the fields and the tools, not the items.

## The macOS signing certificate

A macOS release declares three values of the Developer ID item:

```text
MACOS_CERT_P12       <Developer ID item>#certificate_p12_base64
MACOS_CERT_PASSWORD  <Developer ID item>#certificate_password
MACOS_SIGN_IDENTITY  <Developer ID item>#sign_identity
```

`scripts/apple-developer-id.py` is the tool for that item. It reads an App Store
Connect key from this vault rather than from a file, so no key material lands on
disk, and writes the item as one canonical `bundle` payload through stdin, so no
secret is ever a command-line argument:

```sh
python3 scripts/apple-developer-id.py roles   # who may do what
python3 scripts/apple-developer-id.py list    # what the account already holds
python3 scripts/apple-developer-id.py mint    # create one and store it
```

A Developer ID Application certificate is one Apple issues only to the Account
Holder, so the API cannot mint it; Weles signs in as the Account Holder on a
tracked trajectory, one authorization per password submit, and a Stado relay
captures the second factor in the registered desktop session and stores it in
the execution host's one-use Skarbiec challenge. The whole procedure, both
paths and the recorded provenance of a certificate the API already issued, is
[Apple Developer Certificates](https://skarbiec.wisent.com/docs/apple-developer-certificates).

## The iOS signing material

Every `*-ios` release manifest and TestFlight workflow declares four values:

```text
IOS_DIST_P12_B64        <iOS distribution item>#certificate_p12_base64
IOS_DIST_P12_PASSWORD   <iOS distribution item>#certificate_password
IOS_SIGN_IDENTITY       <iOS distribution item>#sign_identity
IOS_PROFILE_B64         <repository>-signing#provisioning_profile_base64
```

`scripts/apple-ios-signing.py` is the tool for those items, built on the same
`apple_asc.py` helpers as the Developer ID tool. An iOS distribution certificate
is not reserved for the Account Holder, so the whole path is the App Store
Connect API: the certificate from a CSR generated locally, the bundle id by
identifier, the App Store profile from the two, and the GitHub Actions secrets
of one repository piped into `gh secret set` through stdin: the signing values
above plus `WISENT_PACKAGES_TOKEN`, the vault's GitHub token, with which a
GitHub-hosted runner clones the private Swift packages:

```sh
python3 scripts/apple-ios-signing.py list                     # certificates, bundle ids, apps, profiles
python3 scripts/apple-ios-signing.py mint-certificate         # once per certificate; refuses to overwrite
python3 scripts/apple-ios-signing.py profile \
  --repository <repository> --bundle-id <bundle id> --app-name <name>
python3 scripts/apple-ios-signing.py app-record \
  --bundle-id <bundle id> --app-name <name> --sku <sku>
python3 scripts/apple-ios-signing.py check-login              # one sign-in, nothing else
python3 scripts/apple-ios-signing.py publish --repository <repository>
```

A profile cannot be changed at Apple, so one that exists under the pinned name
but names a revoked certificate is deleted and recreated, and the tool says so.

The one write the API refuses is the App Store Connect app record itself
(`POST /v1/apps` answers "The resource 'apps' does not allow 'CREATE'"), which a
TestFlight upload needs to exist. For that write `scripts/apple_web.py` does
what the site does, with no browser: an SRP-6a sign-in at `idmsa.apple.com`
with the Apple ID the vault holds, the second factor read from the
trusted-device prompt by Stado's signed `stado-apple-challenge-capture` helper
(checked before the password is submitted, and installed for the desktop user
the registry binds the account to), and then `iris/v1/apps`, carrying the
`appStoreVersionLocalizations` relationship that endpoint refuses the create
without. `profile` runs it when the bundle id has no record; `app-record` runs
it alone. The trusted session's cookies stay owner-only under `~/.stado/work`,
so a second run inside Apple's trust window signs in without a prompt.

`check-login` proves the Apple ID's password: one sign-in and nothing else,
with a cookie jar of its own, because a run inside the trusted session would
answer "fine" without ever sending the password. A password nothing checks is
a password nobody knows is wrong, so every item holding that Apple ID is
checked this way after it changes.
