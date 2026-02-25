use std::io::Read;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use ctap_types::serde::cbor_deserialize;
use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use iced::widget::{Space, button, column, row, text};
use iced::window::Settings;
use iced::{Alignment, Color, Element, Length, Task, Theme};

use passkeyd_share::{OtherUI, title_bar_component};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
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
        if matches!(msg, UserResponse::Authorize) {
            IS_AUTHORIZED.store(true, std::sync::atomic::Ordering::SeqCst);
            return iced::exit();
        };
        Task::none()
    }

    fn view(&self) -> Element<'_, UserResponse> {
        let title_bar = title_bar_component("hello", UserResponse::Deny);

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
        .color(Color::from_rgb(0.8, 0.8, 0.8))
        .size(16);

        let site = passkeyd_share::select_component(&self.rp, &self.other_ui, None)
            .align_y(Alignment::Center)
            .height(Length::Fill);
        let body = column![description, site].padding([20, 0]);
        let approve = button("Authorize").on_press(UserResponse::Authorize);

        let footer = row![Space::new().width(Length::Fill), approve]
            .width(Length::Fill)
            .padding([0, 30]);

        column![title_bar, body, footer].padding([16, 16]).into()
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
            width: 450.0,
            height: 250.0,
        },
        level: iced::window::Level::AlwaysOnTop,
        ..Default::default()
    })
    .decorations(false)
    .theme(|_state: &AuthorizationUI| Theme::Dracula)
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

    use std::{io::Write, process::Stdio};

    use ctap_types::serde::cbor_serialize;

    use super::*;

    #[test]
    fn test() {
        let mut bufferrrr = [0; 10000];
        let otherui = OtherUI {
            site_icon: None,
            user_icon: None,
            user: ctap_types::webauthn::PublicKeyCredentialUserEntity {
                id: ctap_types::Bytes::from_slice(&[1u8; 64]).expect(""),
                icon: None,
                name: Some("test".into()),
                display_name: Some("hello".into()),
            },
        };

        let values = AuthorizationUI {
            other_ui: otherui,
            rp: PublicKeyCredentialRpEntity {
                id: "github.com".into(),
                name: Some("github".into()),
                icon: None,
            },
        };
        let x = cbor_serialize(&values, &mut bufferrrr[..]).expect("");

        // debug!("spawning ui");
        let mut command = std::process::Command::new("systemd-run")
            .arg(format!("--machine={}@", 1000))
            .arg("--user")
            .arg("--collect")
            .arg("--wait")
            .arg("--quiet")
            .arg("--pipe")
            // .env("SYSTEMD_LOG_LEVEL", "debug")
            .arg(format!(
                "/home/stranger/Code/passkey/target/debug/{}",
                "passkeyd-enroll"
            ))
            // .arg("/usr/lib/passkeyd/passkeyd-enroll")
            .stdin(Stdio::piped())
            .spawn()
            .expect("Failed to spawn UI, are you root?");

        {
            let mut stdin = command.stdin.take().expect("Failed to get stdin");
            stdin.write_all(&x).expect("Failed to write into pipe");
        }
        let result = command.wait().expect("failed to collect ui response");
        let g = result.code().unwrap_or(1);
        assert_eq!(g, 0)
    }
}
