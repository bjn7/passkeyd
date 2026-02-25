<div align="center">
  <img src="https://raw.githubusercontent.com/bjn7/passkeyd/main/icons/banner-passkeyd-2.png" alt="Alt text" width="512">
  <br><br>
  <strong>An Opinionated WebAuthn Authenticator Backed by a TPM</strong>
</div>

---

## About

Passkeyd is an implementation of a WebAuthn authenticator that uses a Trusted Platform Module (TPM) to manage passkeys and perform cryptographic operations securely.

### Contrubution

There is a strong need for contributions. If you are willing to contribute, refer to [CONTRIBUTIONS.md](https://github.com/bjn7/passkeyd/blob/main/CONTRIBUTIONS.md)

### Installation

#### Install Binaries

The package is aviable in the [passkeyd](https://aur.archlinux.org/packages/passkeyd) <sup>AUR</sup>, which you can install using aur helper, For exmaple

```bash
# Using yay
yay -S passkeyd

# Using paru
paru -S passkeyd

# Using aura
aura -A passkeyd

```

#### Start the Passkeyd Service

```bash
sudo systemctl start passkeyd

```

#### Testing the Passkey Authentication

1. Go to the [Passkey Demo Site](https://browser-passkey-demo.vercel.app)
2. Enter the username "Test" and press Sign up.
3. Refresh the site (this will automatically log you out of the "Test" account).
4. Click Sign in. A popup will appear, select the recently added account "Test".
5. A passphrase popup will appear, Enter your logged-in Linux user passphrase.

The UI is a bit wonky and needs some polish. Customization features are coming soon.

### Alternatives

- ~~[libwebauthn](https://github.com/linux-credentials/libwebauthn)~~: TPM 2.0 support is marked as '**planned**' and appears to have been in that status since 2020.

- [tpm-fido](https://github.com/psanford/tpm-fido): Likely to work for a long time due to the longevity of TPM 2.0 and protocol considerations, but it was last updated 3 years ago, so it doesn’t appear to be actively maintained.

- [linux-id](https://github.com/matejsmycka/linux-id): A fork of [tpm-fido](https://github.com/psanford/tpm-fido) that is actively maintained.
