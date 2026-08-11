use ctap_types::serde::cbor_deserialize;
use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use cxx_qt_lib::{QQmlApplicationEngine, QQuickStyle, QString, QUrl};
use cxx_qt_lib_extras::QApplication;
use passkeyd_abi::database::layout::OtherUI;
use passkeyd_abi::utils::CborVec;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::{Read, Write};
use std::pin::Pin;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub struct SelectionUI {
    pub rp: PublicKeyCredentialRpEntity,
    pub other_uis: Vec<OtherUI>,
    pub no_pass: bool,
}

#[derive(Serialize)]
pub struct SelectionResponse<'a> {
    pub index: usize,
    pub passphrase: &'a str,
}

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;

        include!("cxx-qt-lib/qstringlist.h");
        type QStringList = cxx_qt_lib::QStringList;
    }

    #[auto_cxx_name]
    unsafe extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qproperty(QString, select_title)]
        #[qproperty(QString, select_desc)]
        #[qproperty(QString, auth_title)]
        #[qproperty(QString, auth_desc)]
        #[qproperty(QString, auth_helper)]
        #[qproperty(QString, site_id)]
        #[qproperty(QStringList, accounts)]
        #[qproperty(bool, skip_selection)]
        #[qproperty(bool, is_invalid)]
        #[qproperty(u32, retry_count)]
        #[qproperty(u32, selected_index)]
        #[qproperty(bool, skip_password)]
        type SelectionState = super::SelectionStateRust;

        #[qinvokable]
        fn select_account(self: Pin<&mut SelectionState>, index: u32);

        #[qinvokable]
        fn authorize(self: Pin<&mut SelectionState>, password: QString);

        #[qinvokable]
        fn deny(&self);
    }
}

pub struct SelectionStateRust {
    select_title: cxx_qt_lib::QString,
    select_desc: cxx_qt_lib::QString,
    auth_title: cxx_qt_lib::QString,
    auth_desc: cxx_qt_lib::QString,
    auth_helper: cxx_qt_lib::QString,
    site_id: cxx_qt_lib::QString,
    accounts: cxx_qt_lib::QStringList,
    skip_selection: bool,
    skip_password: bool,
    is_invalid: bool,
    retry_count: u32,
    selected_index: u32,
}

impl Default for SelectionStateRust {
    fn default() -> Self {
        let mut state_buffer = Vec::new();
        std::io::stdin().read_to_end(&mut state_buffer).unwrap_or(0);
        let ui_data: SelectionUI = cbor_deserialize(&state_buffer).expect("Invalid CBOR");

        let rp_id = ui_data.rp.id.as_str();

        let select_title_str = passkeyd_locale::translate!("ui.select.select.title_bar");
        let select_desc_str =
            passkeyd_locale::translate!("ui.select.select.description", site => rp_id);
        let auth_title_str = passkeyd_locale::translate!("ui.select.authorize.title_bar");
        let auth_desc_str = passkeyd_locale::translate!("ui.select.authorize.description");
        let auth_helper_str = passkeyd_locale::translate!("ui.select.authorize.helper_text");

        let skip_selection = ui_data.other_uis.len() <= 1;
        let skip_password = ui_data.no_pass;

        if skip_selection && skip_password {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(&[0x02]); // Start of Text

            let report = CborVec::from_serializable(
                SelectionResponse {
                    index: 0,
                    passphrase: "",
                },
                std::mem::size_of::<SelectionResponse>(),
            );

            let _ = stdout.write_all(&report.into_inner());
            let _ = stdout.flush();
            std::process::exit(0);
        }

        let mut accounts = cxx_qt_lib::QStringList::default();

        ui_data.other_uis.iter().for_each(|ui| {
            accounts.append(
                ui.user
                    .display_name
                    .as_ref()
                    .or(ui.user.name.as_ref())
                    .map(|s| cxx_qt_lib::QString::from(s.as_str()))
                    .unwrap_or_else(|| {
                        cxx_qt_lib::QString::from(
                            String::from_utf8_lossy(ui.user.id.as_slice()).as_ref(),
                        )
                    }),
            );
        });

        Self {
            select_title: cxx_qt_lib::QString::from(&select_title_str.to_string()),
            select_desc: cxx_qt_lib::QString::from(&select_desc_str.to_string()),
            auth_title: cxx_qt_lib::QString::from(&auth_title_str.to_string()),
            auth_desc: cxx_qt_lib::QString::from(&auth_desc_str.to_string()),
            auth_helper: cxx_qt_lib::QString::from(&auth_helper_str.to_string()),
            site_id: cxx_qt_lib::QString::from(rp_id),
            accounts,
            skip_selection,
            skip_password,
            is_invalid: false,
            retry_count: 0,
            selected_index: 0,
        }
    }
}

impl qobject::SelectionState {
    pub fn select_account(mut self: Pin<&mut Self>, index: u32) {
        self.as_mut().set_selected_index(index);
        if self.skip_password {
            let idx = index as usize;
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(&[0x02]); // Start of Text

            let report = CborVec::from_serializable(
                SelectionResponse {
                    index: idx,
                    passphrase: "",
                },
                std::mem::size_of::<SelectionResponse>(),
            );

            let _ = stdout.write_all(&report.into_inner());
            let _ = stdout.flush();

            std::process::exit(0);
        }
    }

    pub fn authorize(mut self: Pin<&mut Self>, password: QString) {
        let mut pwd_str = password.to_string();
        let login = whoami::username().expect("Failed to get username??");
        let mut client =
            pam::Client::with_password("system-auth").expect("Failed to init PAM client!");
        client.conversation_mut().set_credentials(login, &pwd_str);

        let retry = *self.retry_count();
        if client.authenticate().is_ok() || retry >= 3 {
            let idx = *self.selected_index() as usize;

            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(&[0x02]); // Start of Text

            let report = CborVec::from_serializable(
                SelectionResponse {
                    index: idx,
                    passphrase: &pwd_str,
                },
                std::mem::size_of::<SelectionResponse>(),
            );

            let _ = stdout.write_all(&report.into_inner());
            let _ = stdout.flush();

            pwd_str.zeroize();
            std::process::exit(0);
        } else {
            self.as_mut().set_retry_count(retry + 1);
            self.as_mut().set_is_invalid(true);
        }
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
            "qrc:/qt/qml/passkeyd/ui/select/src/qml/Main.qml",
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
    fn test_passkey_selection_process() {
        let mut buffer = [0; 10000];
        let other_uis = (0..=5)
            .map(|idx| OtherUI {
                site_icon: None,
                user_icon: None,
                user: ctap_types::webauthn::PublicKeyCredentialUserEntity {
                    id: ctap_types::Bytes::from_slice(&[1u8; 64])
                        .expect("Failed to create user ID"),
                    icon: None,
                    name: Some("Github".into()),
                    display_name: Some(format!("acc-{idx}").as_str().into()),
                },
            })
            .collect::<Vec<_>>();

        let selection_ui = SelectionUI {
            rp: PublicKeyCredentialRpEntity {
                id: "github.com".into(),
                name: Some("Github".into()),
                icon: None,
            },
            no_pass: false,
            other_uis,
        };

        let serialized_data =
            cbor_serialize(&selection_ui, &mut buffer[..]).expect("Serialization failed");

        let passkeyd_select_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../target/debug/passkeyd-kde-select");

        let mut command = std::process::Command::new("systemd-run")
            .arg(format!("--machine={}@", 1000))
            .arg("--user")
            .arg("--collect")
            .arg("--wait")
            .arg("--quiet")
            .arg("--pipe")
            .arg(passkeyd_select_path.as_os_str())
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
