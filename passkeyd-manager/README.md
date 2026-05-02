<div align="center">
  <img src="https://raw.githubusercontent.com/bjn7/passkeyd/main/icons/banner-passkeyd-2.png" alt="Alt text" width="512">
  <br><br>
  <strong>An Opinionated WebAuthn Authenticator Backed by a TPM</strong>
</div>

---

## About

This includes a simple passkey manager.

To manage your passkeys, enter the command `passkeyd-manager`. Press `Enter` or `Esc` to view the selected site's passkey. Press `Enter` or `Esc` again to go back. Pressing `Delete` while a website is selected will delete all of its passkeys, while pressing, `Delete` when a specific passkey is selected will delete that entry only. This will only remove it from the system, not from the website. After deleting it from the website (you may need to check the website for deletion from their end), you can delete it from your system as well, or vice versa. To exit, press `Ctrl + C`
