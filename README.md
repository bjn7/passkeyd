<div align="center">
  <img src="https://raw.githubusercontent.com/bjn7/passkeyd/main/icons/banner-passkeyd-2.png" alt="Alt text" width="512">
  <br><br>
  <strong>An Opinionated WebAuthn Authenticator</strong>
</div>

---

## About

Passkeyd is a Linux based WebAuthn authenticator that works with any WebAuthn supported application, including browsers. It supports both TPM and non-TPM devices.

## Installation

#### Install Binaries

<details>
<summary>Arch-based distro</summary>
<br>

The package is available in the [passkeyd](https://aur.archlinux.org/packages/passkeyd) <sup>AUR</sup>, which you can install using aur helper, For exmaple

```bash
# Using yay
yay -S passkeyd

# Using paru
paru -S passkeyd

# Using aura
aura -A passkeyd
```

</details>

<details>
<summary>Ubuntu-based distro</summary>
<br>

```bash
curl -fsSL https://github.com/bjn7/passkeyd/releases/latest/download/passkeyd.gpg | sudo tee /usr/share/keyrings/passkeyd.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/passkeyd.gpg] https://github.com/bjn7/passkeyd/releases/latest/download ./' | sudo tee /etc/apt/sources.list.d/passkeyd.list
sudo apt-get update && sudo apt-get install passkeyd
```

</details>

#### Start the Passkeyd Service

<details>
<summary>Initialize Passkeyd</summary>
<br>

Before initializing the `passkeyd` service, you may want to configure it properly for your system, [Initial Required Configuration](https://github.com/bjn7/passkeyd/wiki/Initial-Required-Configuration).

```bash
sudo systemctl enable passkeyd
sudo systemctl start passkeyd
```

</details>

<details>
<summary> Testing the Passkey Authentication (optional)</summary>

<br>

To determine whether the passkey is working properly, you may follow this step.

1. Go to the [Webauthn Demo Site](https://webauthn.io)
2. Enter the username "Test" and click Register.
3. You should see: "Success! Now try to authenticate..."
4. Click authenticate, A passphrase popup will appear, Enter your logged-in Linux user passphrase.
</details>

## Passkeyd UI Custom Theme

The config for theme can be found at `/usr/share/passkeyd/theme.conf`

## Passkeyd Manager

To manage your passkeys, Enter the command `passkeyd-manager`.

<table class="desktop-only">
  <thead>
    <tr>
      <th width="25%">Keys</th>
      <th width="75%">Action</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><kbd>Enter</kbd> or <kbd>Esc</kbd></td>
      <td>View the selected site’s passkey. Press again to go back.</td>
    </tr>
    <tr>
      <td><kbd>Delete</kbd></td>
      <td>If a website is selected, deletes all its passkeys. If a specific passkey is selected, deletes only that entry. This only removes it from the system, not from the website. You may still need to remove it from the website separately.</td>
    </tr>
    <tr>
      <td><kbd>Ctrl</kbd> + <kbd>C</kbd></td>
      <td>Exit.</td>
    </tr>
  </tbody>
</table>

### Contrubution

If you are willing to contribute, refer to [CONTRIBUTING.md](https://github.com/bjn7/passkeyd/blob/main/CONTRIBUTING.md)

### Alternatives

- ~~[libwebauthn](https://github.com/linux-credentials/libwebauthn)~~: TPM 2.0 support is marked as '**planned**' and appears to have been in that status since 2020.

- [tpm-fido](https://github.com/psanford/tpm-fido): Likely to work for a long time due to the longevity of TPM 2.0 and protocol considerations, but it was last updated 3 years ago, so it doesn’t appear to be actively maintained.

- [linux-id](https://github.com/matejsmycka/linux-id): A fork of [tpm-fido](https://github.com/psanford/tpm-fido) that is actively maintained.
