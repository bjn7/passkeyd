use std::io::Read;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use ctap_types::serde::cbor_deserialize;
use iced::widget::{button, column, container, text};
use iced::window::Settings;
use iced::{Alignment, Element, Length, Task};

use passkeyd_share::component::title_bar_component;
use passkeyd_share::theme;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthorizationUI {
    pub description: String,
    pub title: String,
    pub button: String,
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
        let title_bar = title_bar_component(&self.title, UserResponse::Deny);

        let description = text(self.description.as_str())
            .class(theme::TextClass::SecondaryText)
            .size(16);

        let approve = button(
            text(self.button.as_str())
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
                .width(Length::Fill)
                .height(Length::Fixed(24.))
                .line_height(1.),
        )
        .class(theme::ButtonClass::Approval)
        .width(Length::Fill)
        .on_press(UserResponse::Authorize);

        // let footer = column![approve].width(Length::Fill);

        let body_and_footer = container(column![description, approve].spacing(28))
            .align_x(Alignment::Center)
            .height(Length::Fixed(112.))
            .align_y(Alignment::Center);

        column![title_bar, body_and_footer]
            .spacing(16)
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
            height: 254.0,
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
    use std::{env, io::Write, path::PathBuf, process::Stdio};

    #[test]
    fn test_enrollment_process() {
        let mut buffer = [0; 10000];
        let authorization_ui = AuthorizationUI {
            title: "Passkey selection".into(),
            description: "This site is requesting authentication. Use this passkey to proceed."
                .into(),
            button: "Use this passkey".into(),
        };
        let serialized_data =
            cbor_serialize(&authorization_ui, &mut buffer[..]).expect("Serialization failed");
        let passkeyd_enroll_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/debug/passkeyd-selection");
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
