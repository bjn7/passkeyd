use ctap_types::serde::cbor_deserialize;
use gtk4::HeaderBar;
use gtk4::prelude::*;
use gtk4::{Align, Application, ApplicationWindow, Box as GtkBox, Button, Label, Orientation};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::io::Read;
use std::process::ExitCode;
use std::rc::Rc;

#[derive(Serialize, Deserialize)]
pub struct AuthorizationUI {
    pub description: String,
    pub title: String,
    pub button: String,
}

fn main() -> ExitCode {
    passkeyd_locale::init_translations();

    let mut state_buffer = Vec::new();
    std::io::stdin().read_to_end(&mut state_buffer).unwrap_or(0);
    let ui_data: AuthorizationUI = cbor_deserialize(&state_buffer).expect("Invalid CBOR");

    let title_str = ui_data.title;
    let desc_str = ui_data.description;
    let button_str = ui_data.button;

    let exit_code = Rc::new(Cell::new(ExitCode::FAILURE));

    let app = Application::builder()
        .application_id("passkeyd.ui.selection")
        .build();

    let exit_code_clone = exit_code.clone();

    app.connect_activate(move |app| {
        let window = ApplicationWindow::builder()
            .application(app)
            .title(title_str.as_str())
            .default_width(420)
            .default_height(160)
            .resizable(false)
            .build();

        let header_bar = HeaderBar::builder().show_title_buttons(true).build();
        window.set_titlebar(Some(&header_bar));

        let exit_code_close = exit_code_clone.clone();
        window.connect_close_request({
            let app = app.clone();
            move |_| {
                exit_code_close.set(ExitCode::FAILURE);
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
            .label(desc_str.as_str())
            .wrap(true)
            .xalign(0.0)
            .build();

        main_box.append(&desc_label);

        let spacer = GtkBox::builder().vexpand(true).build();
        main_box.append(&spacer);

        let button_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .halign(Align::End)
            .valign(Align::End)
            .build();

        let authorize_button = Button::builder().label(button_str.as_str()).build();

        authorize_button.add_css_class("suggested-action");
        authorize_button.set_cursor_from_name(Some("pointer"));

        authorize_button.connect_clicked({
            let app = app.clone();
            let exit_code_clone = exit_code_clone.clone();
            move |_| {
                exit_code_clone.set(ExitCode::SUCCESS);
                app.quit();
            }
        });

        button_box.append(&authorize_button);
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
    use std::{env, io::Write, path::PathBuf, process::Stdio};

    #[test]
    fn test_selection_process() {
        let mut buffer = [0; 10000];
        let authorization_ui = AuthorizationUI {
            title: "Passkey selection".into(),
            description: "This site is requesting authentication. Use this passkey to proceed."
                .into(),
            button: "Use this passkey".into(),
        };

        let serialized_data =
            cbor_serialize(&authorization_ui, &mut buffer[..]).expect("Serialization failed");

        let passkeyd_selection_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../target/debug/passkeyd-gtk-selection");

        let mut command = std::process::Command::new("systemd-run")
            .arg(format!("--machine={}@", 1000))
            .arg("--user")
            .arg("--collect")
            .arg("--wait")
            .arg("--quiet")
            .arg("--pipe")
            .arg(passkeyd_selection_path.as_os_str())
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
