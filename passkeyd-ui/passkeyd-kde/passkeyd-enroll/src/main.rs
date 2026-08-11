use ctap_types::serde::cbor_deserialize;
use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use cxx_qt_lib::{QQmlApplicationEngine, QQuickStyle, QString, QUrl};
use cxx_qt_lib_extras::QApplication;
use passkeyd_abi::database::layout::OtherUI;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::Read;

#[derive(Serialize, Deserialize)]
pub struct AuthorizationUI {
    pub rp: PublicKeyCredentialRpEntity,
    pub other_ui: OtherUI,
}

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    #[auto_cxx_name]
    unsafe extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qproperty(QString, title)]
        #[qproperty(QString, description)]
        #[qproperty(QString, button_text)]
        #[qproperty(QString, site_id)]
        #[qproperty(QString, user_name)]
        type AuthorizationState = super::AuthorizationStateRust;

        #[qinvokable]
        fn authorize(&self);

        #[qinvokable]
        fn deny(&self);
    }
}

pub struct AuthorizationStateRust {
    title: cxx_qt_lib::QString,
    description: cxx_qt_lib::QString,
    button_text: cxx_qt_lib::QString,
    site_id: cxx_qt_lib::QString,
    user_name: cxx_qt_lib::QString,
}

impl Default for AuthorizationStateRust {
    fn default() -> Self {
        let mut state_buffer = Vec::new();
        std::io::stdin().read_to_end(&mut state_buffer).unwrap_or(0);
        let ui_data: AuthorizationUI = cbor_deserialize(&state_buffer).expect("Invalid CBOR");

        let title_str = passkeyd_locale::translate!("ui.enroll.main.title");
        let button_str = passkeyd_locale::translate!("ui.enroll.main.approve");
        let rp_id = ui_data.rp.id.as_str();

        let (desc_str, user_name_str) = if let Some(dname) = &ui_data.other_ui.user.display_name {
            (
                passkeyd_locale::translate!(
                    "ui.enroll.main.description_with_account",
                    site => rp_id,
                    user_account => dname.as_str()
                ),
                dname.as_str().to_string(),
            )
        } else if let Some(name) = &ui_data.other_ui.user.name {
            (
                passkeyd_locale::translate!(
                    "ui.enroll.main.description_with_account",
                    site => rp_id,
                    user_account => name.as_str()
                ),
                name.as_str().to_string(),
            )
        } else if let Ok(id) = std::str::from_utf8(&ui_data.other_ui.user.id) {
            (
                passkeyd_locale::translate!(
                    "ui.enroll.main.description_with_account",
                    site => rp_id,
                    user_account => id
                ),
                id.to_string(),
            )
        } else {
            (
                passkeyd_locale::translate!(
                    "ui.enroll.main.description_without_account",
                    site => rp_id
                ),
                String::new(),
            )
        };

        Self {
            title: cxx_qt_lib::QString::from(&title_str.to_string()),
            description: cxx_qt_lib::QString::from(&desc_str.to_string()),
            button_text: cxx_qt_lib::QString::from(&button_str.to_string()),
            site_id: cxx_qt_lib::QString::from(rp_id),
            user_name: cxx_qt_lib::QString::from(&user_name_str.to_string()),
        }
    }
}

impl qobject::AuthorizationState {
    pub fn authorize(&self) {
        std::process::exit(0);
    }

    pub fn deny(&self) {
        std::process::exit(1);
    }
}

fn main() {
    passkeyd_locale::init_translations();

    let mut app = QApplication::new();
    if env::var("QT_QUICK_CONTROLS_STYLE").is_err() {
        QQuickStyle::set_style(&QString::from("org.kde.desktop"));
    }

    let mut engine = QQmlApplicationEngine::new();
    if let Some(engine) = engine.as_mut() {
        engine.load(&QUrl::from(
            "qrc:/qt/qml/passkeyd/ui/enroll/src/qml/Main.qml",
        ));
    }

    if let Some(app) = app.as_mut() {
        app.exec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctap_types::serde::cbor_serialize;
    use passkeyd_abi::database::layout::OtherUI;
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

        let passkeyd_enroll_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../target/debug/passkeyd-kde-enroll");

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
