use std::io::Read;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use ctap_types::serde::cbor_deserialize;
use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use iced::widget::{button, column, text};
use iced::window::Settings;
use iced::{Alignment, Element, Length, Task};

use passkeyd_share::{component, theme};
use passkeyd_share::{component::title_bar_component, database::layout::OtherUI};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthorizationUI {
    pub rp: PublicKeyCredentialRpEntity,
    pub other_ui: OtherUI,
}

#[derive(Debug, Clone, Copy)]
enum UserResponse {
    Deny,
    Authorize,
}

static IS_AUTHORIZED: AtomicBool = AtomicBool::new(false);
impl AuthorizationUI {
    fn bootfn() -> Self {
        let mut state_buffer = Vec::with_capacity(size_of::<AuthorizationUI>());
        std::io::stdin()
            .read_to_end(&mut state_buffer)
            .expect("Failed to read input");
        cbor_deserialize(&state_buffer).expect("Invalid cbor received")
    }

    fn update(&mut self, msg: UserResponse) -> Task<UserResponse> {
        match msg {
            UserResponse::Authorize => {
                IS_AUTHORIZED.store(true, std::sync::atomic::Ordering::SeqCst);
                return iced::exit();
            }
            UserResponse::Deny => iced::exit(),
        }
    }

    fn view(&self) -> Element<'_, UserResponse, theme::StylisedTheme> {
        let title_bar = title_bar_component("Create Passkey", UserResponse::Deny);

        let description = if let Some(dname) = &self.other_ui.user.display_name {
            text(format!(
                "The site {} is requesting to create a passkey for your user account {}.",
                self.rp.id.as_str(),
                dname.as_str()
            ))
        } else if let Some(name) = &self.other_ui.user.name {
            text(format!(
                "The site {} is requesting to create a passkey for your user account {}.",
                self.rp.id.as_str(),
                name.as_str()
            ))
        } else if let Ok(id) = str::from_utf8(&self.other_ui.user.id) {
            text(format!(
                "The site {} is requesting to create a passkey for your user account {}.",
                self.rp.id.as_str(),
                id
            ))
        } else {
            text(format!(
                "The site {} is requesting to create a passkey for your user account",
                self.rp.id.as_str(),
            ))
        }
        .class(theme::TextClass::SecondaryText)
        .size(16);

        let site = column![component::user_component(&self.rp, &self.other_ui, None)]
            .align_x(Alignment::Center)
            .width(Length::Fill);

        let component_spacing = 18;
        let body = column![description, site].spacing(component_spacing);

        let approve = button(
            text("Authorize")
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
                .width(Length::Fill)
                .height(Length::Fixed(24.))
                .line_height(1.),
        )
        .class(theme::ButtonClass::Approval)
        .width(Length::Fill)
        .on_press(UserResponse::Authorize);

        let footer = column![approve].width(Length::Fill);

        column![title_bar, body, footer]
            .spacing(component_spacing)
            .padding([26, 36])
            .into()
    }
}

pub fn main() -> ExitCode {
    let _ = iced::application(
        AuthorizationUI::bootfn,
        AuthorizationUI::update,
        AuthorizationUI::view,
    )
    .window(Settings {
        maximized: false,
        minimizable: false,
        closeable: false,
        resizable: false,
        size: iced::Size {
            width: 474.0,
            height: 294.0,
        },
        level: iced::window::Level::AlwaysOnTop,
        ..Default::default()
    })
    .decorations(false)
    .theme(|_state: &AuthorizationUI| theme::StylisedTheme::default())
    .run();

    let is_auth = IS_AUTHORIZED.load(std::sync::atomic::Ordering::SeqCst);
    if is_auth {
        return ExitCode::SUCCESS;
    } else {
        return ExitCode::FAILURE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctap_types::serde::cbor_serialize;
    use passkeyd_share::database::layout::OtherUI;
    use std::{env, io::Write, path::PathBuf, process::Stdio};

    #[test]
    fn test_enrollment_process() {
        let mut buffer = [0; 10000];
        let other_ui = OtherUI {
            site_icon: None,
            user_icon: None,
            user: ctap_types::webauthn::PublicKeyCredentialUserEntity {
                id: ctap_types::Bytes::from_slice(&[1u8; 64]).expect("Failed to create user ID"),
                icon: None,
                name: Some("Github".into()),
                display_name: Some("space90".into()),
            },
        };

        let authorization_ui = AuthorizationUI {
            other_ui,
            rp: PublicKeyCredentialRpEntity {
                id: "github.com".into(),
                name: Some("Github".into()),
                icon: None,
            },
        };
        let serialized_data =
            cbor_serialize(&authorization_ui, &mut buffer[..]).expect("Serialization failed");
        let passkeyd_enroll_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/debug/passkeyd-enroll");
        let mut command = std::process::Command::new("systemd-run")
            .arg(format!("--machine={}@", 1000))
            .arg("--user")
            .arg("--collect")
            .arg("--wait")
            .arg("--quiet")
            .arg("--pipe")
            .arg(passkeyd_enroll_path.as_os_str())
            .stdin(Stdio::piped())
            .spawn()
            .expect("Failed to spawn UI process. Are you root?");

        {
            let mut stdin = command.stdin.take().expect("Failed to get stdin");
            stdin
                .write_all(&serialized_data)
                .expect("Failed to write data into pipe");
        }

        let result = command.wait().expect("Failed to collect UI response");
        let exit_code = result.code().unwrap_or(1);

        assert_eq!(exit_code, 0);
    }
}
