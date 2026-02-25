## Contributions

For any significant contribution, for example, working on any TODO item, CTAP2 command, or CTAPHID make sure to open an issue explicitly describing what you are going to work on. Also, check whether someone is already working on it before opening a new issue.

For non-significant changes such as refactoring, renaming variables, or making small logic adjustments, opening an issue is not required.

Use of `unsafe` is allowed, but make sure to leave a comment above unsafe keyword the how saftey is granted.

All implementation details are described in the FIDO v2.1 specification:
[fidoalliance.org/specs/fido-v2.1-ps](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)

## IMPORTANT

Currently, the current primary target of the project is GUI refinement/polishing. For your reference, the GUI is built using the iced crate. The secondary to-do is to allow users to bring their own themes, aka customization.

### UI Flow

For **MakeCredential** requests, the user should not be required to provide a PIN. Instead, only user consent should be requested. Do not follow the UP/UV option specs here.

For **GetCredential** requests, the user should be prompted to select a user account, followed by entering the passphrase of the user's Linux account. Do not follow the UP/UV option specs here.

## IMPORTANT - GUI

If you have improvements or fresh ideas for the UI, create a design and include a Figma link or a PNG in the issue.

I’ve already designed an acceptable MakeCredential UI, which is in assets folder with [MakeCerds - Title and logo.jpg](https://github.com/bjn7/passkeyd/blob/main/assets/MakeCerds%20-%20Title%20and%20logo.jpg) [MakeCerds - Title only.jpg](https://github.com/bjn7/passkeyd/blob/main/assets/MakeCerds%20-%20Title%20only.jpg) and finally [MakeCerds - Titleless.jpg](https://github.com/bjn7/passkeyd/blob/main/assets/MakeCerds%20-%20Titleless.jpg). For GetCredential or any other UI, make sure it aligns with the style and vibe of the MakeCredential design.
