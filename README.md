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

#### Configure UID

Run the command `id -u`, then modify the `GUI_UID` value in `/etc/passkeyd.conf` to match the `GUI_UID` returned by `id -u`. It is usually `1000`.

```diff
- GUI_UID=1000   # The UID of the user allowed to run GUI components (typically a normal desktop user)
+ GUI_UID=PLACE_YOUR_UID_HERE # The UID of the user allowed to run GUI components (typically a normal desktop user)
RUST_LOG=info  # logging level for passkeyd

# Advanced option: The front-end UI for selecting a passkey
FRONT_ENROLL=passkeyd-enroll

# Advanced option: The front-end UI for for passkey creation
FRONT_SELECT=passkeyd-select

# Advanced option: The front-end UI for verifying the user's presence.
FRONT_SELECTION=passkeyd-selection
```

#### Start the Passkeyd Service

```bash
sudo systemctl enable passkeyd
sudo systemctl start passkeyd
```

#### Testing the Passkey Authentication

1. Go to the [Webauthn Demo Site](https://webauthn.io)
2. Enter the username "Test" and click Register.
3. You should see: "Success! Now try to authenticate..."
4. Click authenticate, A passphrase popup will appear, Enter your logged-in Linux user passphrase.

> Note: It works perfectly with Chromium-based browsers (e.g., Chrome, Brave, etc.). However, you may encounter issues in Firefox. If you experience any problems, open an issue.

### Passkeyd Config

A passkey can be configured via `/etc/passkeyd.conf`. Only the user's UUID mentioned in the passkeyd configuration file can authorize the request.

```bash
GUI_UID=1000   # The UID of the user allowed to run GUI components (typically a normal desktop user)
RUST_LOG=info  # logging level for passkeyd

# Advanced option: The front-end UI for selecting a passkey
FRONT_ENROLL=passkeyd-enroll

# Advanced option: The front-end UI for for passkey creation
FRONT_SELECT=passkeyd-select

# Advanced option: The front-end UI for verifying the user's presence.
FRONT_SELECTION=passkeyd-selection
```

### Passkeyd UI Custom Theme

By default passkeyd uses `passkeyd-enroll`, `passkeyd-select` and `passkeyd-selection` for the front-end user interface, the config for theme can be found at `/usr/share/passkeyd/theme.conf`

```toml
# Format: [r, g, b, a]
# Each value must be between 0-255.
# 'r' represents the red channel
# 'g' represents the green channel
# 'b' represents the blue channel
# 'a' represents the alpha channel, which determines the transparency of the color.

background = [36, 37, 50, 255]  # Background color (dark shade)
primary_text = [255, 255, 255, 255]  # Primary text color (for title, approval buttons)
secondary_text = [230, 230, 230, 255]  # Secondary text color (for descriptions)
surface = [45, 40, 60, 255]  # Surface color (used for elevated surfaces)
surface_primary_text = [236, 217, 217, 255]  # Text color for site name within elevated surfaces
surface_secondary_text = [236, 217, 217, 255]  # Text color for site username within elevated surfaces
accent = [160, 135, 255, 255]  # Accent color (used for button backgrounds)
scrollbar_track = [115, 115, 115, 25]  # Scrollbar track color (background of the scrollbar)
scrollbar_thumb = [80, 80, 80, 90]  # Scrollbar thumb color (movable part of the scrollbar)
```

The UI front-end can be swapped and is fully customizable For more information about creating your own custom UI, head to [Custom UI Frontend](https://github.com/bjn7/passkeyd/wiki/Custom-UI-Frontend)

### Passkey Manager

To manage your passkeys, enter the command `passkeyd-manager`. Press `Enter` or `Esc` to view the selected site's passkey. Press `Enter` or `Esc` again to go back. Pressing `Delete` while a website is selected will delete all of its passkeys, while pressing, `Delete` when a specific passkey is selected will delete that entry only. This will only remove it from the system, not from the website. After deleting it from the website (you may need to check the website for deletion from their end), you can delete it from your system as well, or vice versa. To exit, press `Ctrl + C`

### Alternatives

- ~~[libwebauthn](https://github.com/linux-credentials/libwebauthn)~~: TPM 2.0 support is marked as '**planned**' and appears to have been in that status since 2020.

- [tpm-fido](https://github.com/psanford/tpm-fido): Likely to work for a long time due to the longevity of TPM 2.0 and protocol considerations, but it was last updated 3 years ago, so it doesn’t appear to be actively maintained.

- [linux-id](https://github.com/matejsmycka/linux-id): A fork of [tpm-fido](https://github.com/psanford/tpm-fido) that is actively maintained.
