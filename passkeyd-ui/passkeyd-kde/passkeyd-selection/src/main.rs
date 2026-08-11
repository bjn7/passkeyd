use ctap_types::serde::cbor_deserialize;
use cxx_qt_lib::{QQmlApplicationEngine, QQuickStyle, QString, QUrl};
use cxx_qt_lib_extras::QApplication;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::Read;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationUI {
    pub description: String,
    pub title: String,
    pub button: String,
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
}

impl Default for AuthorizationStateRust {
    fn default() -> Self {
        let mut state_buffer = Vec::new();
        std::io::stdin().read_to_end(&mut state_buffer).unwrap_or(0);
        let ui_data: AuthorizationUI = cbor_deserialize(&state_buffer).expect("Invalid CBOR");

        Self {
            title: cxx_qt_lib::QString::from(&ui_data.title),
            description: cxx_qt_lib::QString::from(&ui_data.description),
            button_text: cxx_qt_lib::QString::from(&ui_data.button),
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
            "qrc:/qt/qml/passkeyd/ui/selection/src/qml/Main.qml",
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
        let passkeyd_enroll_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../target/debug/passkeyd-kde-selection");

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
