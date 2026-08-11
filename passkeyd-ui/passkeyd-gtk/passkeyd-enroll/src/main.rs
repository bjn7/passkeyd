use ctap_types::serde::cbor_deserialize;
use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use gtk4::HeaderBar;
use gtk4::pango;
use gtk4::prelude::*;
use gtk4::{
    Align, Application, ApplicationWindow, Box as GtkBox, Button, Grid, Label, Orientation,
};
use passkeyd_abi::database::layout::OtherUI;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::io::Read;
use std::process::ExitCode;
use std::rc::Rc;

#[derive(Serialize, Deserialize)]
pub struct AuthorizationUI {
    pub rp: PublicKeyCredentialRpEntity,
    pub other_ui: OtherUI,
}

fn main() -> ExitCode {
    passkeyd_locale::init_translations();

    let mut state_buffer = Vec::new();
    std::io::stdin().read_to_end(&mut state_buffer).unwrap_or(0);
    let ui_data: AuthorizationUI = cbor_deserialize(&state_buffer).expect("Invalid CBOR");

    let title_str = passkeyd_locale::translate!("ui.enroll.main.title");
    let button_str = passkeyd_locale::translate!("ui.enroll.main.approve");
    let rp_id = ui_data.rp.id.as_str().to_string();

    let (desc_str, user_name_str) = if let Some(dname) = &ui_data.other_ui.user.display_name {
        (
            passkeyd_locale::translate!(
                "ui.enroll.main.description_with_account",
                site => rp_id.as_str(),
                user_account => dname.as_str()
            ),
            dname.as_str().to_string(),
        )
    } else if let Some(name) = &ui_data.other_ui.user.name {
        (
            passkeyd_locale::translate!(
                "ui.enroll.main.description_with_account",
                site => rp_id.as_str(),
                user_account => name.as_str()
            ),
            name.as_str().to_string(),
        )
    } else if let Ok(id) = std::str::from_utf8(&ui_data.other_ui.user.id) {
        (
            passkeyd_locale::translate!(
                "ui.enroll.main.description_with_account",
                site => rp_id.as_str(),
                user_account => id
            ),
            id.to_string(),
        )
    } else {
        (
            passkeyd_locale::translate!(
                "ui.enroll.main.description_without_account",
                site => rp_id.as_str()
            ),
            String::new(),
        )
    };

    let exit_code = Rc::new(Cell::new(ExitCode::FAILURE));

    let app = Application::builder()
        .application_id("passkeyd.ui.enroll")
        .build();

    let exit_code_clone = exit_code.clone();

    app.connect_activate(move |app| {
        let window = ApplicationWindow::builder()
            .application(app)
            .title(title_str.as_ref())
            .default_width(420)
            .default_height(210)
            .resizable(false)
            .build();

        let header_bar = HeaderBar::builder().show_title_buttons(true).build();

        window.set_titlebar(Some(&header_bar));

        window.connect_close_request({
            let app = app.clone();
            move |_| {
                app.quit();
                gtk4::glib::Propagation::Stop
            }
        });

        let main_box = GtkBox::builder()
            .orientation(Orientation::Vertical)
            .margin_start(16)
            .margin_end(16)
            .margin_top(16)
            .margin_bottom(16)
            .spacing(12)
            .build();

        let desc_label = Label::builder()
            .label(desc_str.as_ref())
            .wrap(true)
            .xalign(0.0)
            .build();

        main_box.append(&desc_label);

        // gite / name
        let grid = Grid::builder().row_spacing(6).column_spacing(12).build();

        let site_title = Label::builder()
            .label("<b>Site:</b>")
            .use_markup(true)
            .xalign(0.0)
            .build();

        let site_value = Label::builder()
            .label(&rp_id)
            .ellipsize(pango::EllipsizeMode::End)
            .xalign(0.0)
            .hexpand(true)
            .build();

        grid.attach(&site_title, 0, 0, 1, 1);
        grid.attach(&site_value, 1, 0, 1, 1);

        if !user_name_str.is_empty() {
            let name_title = Label::builder()
                .label("<b>Name:</b>")
                .use_markup(true)
                .xalign(0.0)
                .build();
            let name_value = Label::builder()
                .label(&user_name_str)
                .ellipsize(pango::EllipsizeMode::End)
                .xalign(0.0)
                .hexpand(true)
                .build();

            grid.attach(&name_title, 0, 1, 1, 1);
            grid.attach(&name_value, 1, 1, 1, 1);
        }

        main_box.append(&grid);

        let spacer = GtkBox::builder().vexpand(true).build();
        main_box.append(&spacer);

        let button_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .halign(Align::End)
            .valign(Align::End)
            .build();

        let approve_button = Button::builder().label(button_str.as_ref()).build();

        approve_button.add_css_class("suggested-action");
        approve_button.set_cursor_from_name(Some("pointer"));

        approve_button.connect_clicked({
            let app = app.clone();
            let exit_code_clone = exit_code_clone.clone();
            move |_| {
                exit_code_clone.set(ExitCode::SUCCESS);
                app.quit();
            }
        });

        button_box.append(&approve_button);
        main_box.append(&button_box);

        window.set_child(Some(&main_box));
        window.present();
    });

    app.run_with_args::<&str>(&[]);
    exit_code.get()
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
            .join("../../../target/debug/passkeyd-gtk-enroll");

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
