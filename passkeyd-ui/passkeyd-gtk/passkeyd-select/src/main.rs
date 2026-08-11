use ctap_types::serde::cbor_deserialize;
use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use gtk4::pango;
use gtk4::prelude::*;
use gtk4::{
    Align, Application, ApplicationWindow, Box as GtkBox, Button, Entry, Image, Label, ListBox,
    ListBoxRow, Orientation, ScrolledWindow, Stack,
};
use passkeyd_abi::database::layout::OtherUI;
use passkeyd_abi::utils::CborVec;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::io::{Read, Write};
use std::process::ExitCode;
use std::rc::Rc;
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

fn main() -> ExitCode {
    passkeyd_locale::init_translations();

    let mut state_buffer = Vec::new();
    std::io::stdin().read_to_end(&mut state_buffer).unwrap_or(0);
    let ui_data: SelectionUI = cbor_deserialize(&state_buffer).expect("Invalid CBOR");

    let rp_id = ui_data.rp.id.as_str().to_string();

    let select_title_str = passkeyd_locale::translate!("ui.select.select.title_bar");
    let select_desc_str =
        passkeyd_locale::translate!("ui.select.select.description", site => rp_id.as_str());
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
        return ExitCode::SUCCESS;
    }

    let exit_code = Rc::new(Cell::new(ExitCode::FAILURE));
    let selected_index = Rc::new(Cell::new(0usize));
    let retry_count = Rc::new(Cell::new(0u32));

    let app = Application::builder()
        .application_id("passkeyd.ui.select")
        .build();

    let exit_code_clone = exit_code.clone();
    let selected_index_clone = selected_index.clone();
    let retry_count_clone = retry_count.clone();
    let other_uis = ui_data.other_uis;

    app.connect_activate(move |app| {
        let window = ApplicationWindow::builder()
            .application(app)
            .title(if skip_selection {
                auth_title_str.as_ref()
            } else {
                select_title_str.as_ref()
            })
            .default_width(420)
            .default_height(230)
            .resizable(false)
            .build();

        let header_bar = gtk4::HeaderBar::builder().show_title_buttons(true).build();
        window.set_titlebar(Some(&header_bar));

        window.connect_close_request({
            let app = app.clone();
            let exit_code_clone = exit_code_clone.clone();
            move |_| {
                exit_code_clone.set(ExitCode::FAILURE);
                app.quit();
                gtk4::glib::Propagation::Stop
            }
        });

        let stack = Stack::new();
        stack.set_transition_type(gtk4::StackTransitionType::SlideLeftRight);

        let select_box = GtkBox::builder()
            .orientation(Orientation::Vertical)
            .margin_start(16)
            .margin_end(16)
            .margin_top(16)
            .margin_bottom(16)
            .spacing(12)
            .build();

        let select_desc_label = Label::builder()
            .label(select_desc_str.as_ref())
            .wrap(true)
            .xalign(0.0)
            .build();
        select_box.append(&select_desc_label);

        let list_box = ListBox::new();
        list_box.add_css_class("boxed-list");

        for ui in &other_uis {
            let display_text = ui
                .user
                .display_name
                .as_ref()
                .or(ui.user.name.as_ref())
                .map(|s| s.to_string())
                .unwrap_or_else(|| String::from_utf8_lossy(ui.user.id.as_slice()).to_string());

            let row = ListBoxRow::new();
            row.set_cursor_from_name(Some("pointer"));
            let row_box = GtkBox::builder()
                .orientation(Orientation::Horizontal)
                .spacing(12)
                .margin_start(12)
                .margin_end(12)
                .margin_top(10)
                .margin_bottom(10)
                .build();

            let icon = Image::from_icon_name("avatar-default-symbolic");
            icon.set_pixel_size(16);
            row_box.append(&icon);

            let row_label = Label::builder()
                .label(&display_text)
                .xalign(0.0)
                .hexpand(true)
                .ellipsize(pango::EllipsizeMode::End)
                .build();
            row_box.append(&row_label);

            row.set_child(Some(&row_box));
            list_box.append(&row);
        }

        let scrolled_window = ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .vscrollbar_policy(gtk4::PolicyType::Automatic)
            .min_content_height(100)
            .max_content_height(140)
            .child(&list_box)
            .build();

        select_box.append(&scrolled_window);

        let auth_box = GtkBox::builder()
            .orientation(Orientation::Vertical)
            .margin_start(16)
            .margin_end(16)
            .margin_top(16)
            .margin_bottom(16)
            .spacing(12)
            .build();

        let auth_desc_label = Label::builder()
            .label(auth_desc_str.as_ref())
            .wrap(true)
            .xalign(0.0)
            .build();
        auth_box.append(&auth_desc_label);

        let password_entry = Entry::builder()
            .visibility(false)
            .placeholder_text("Password")
            .hexpand(true)
            .build();
        auth_box.append(&password_entry);

        let helper_label = Label::builder()
            .label(auth_helper_str.as_ref())
            .wrap(true)
            .xalign(0.0)
            .visible(false)
            .build();
        helper_label.add_css_class("error");
        auth_box.append(&helper_label);

        let spacer = GtkBox::builder().vexpand(true).build();
        auth_box.append(&spacer);

        let button_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .halign(Align::End)
            .valign(Align::End)
            .spacing(8)
            .build();

        let authorize_button = Button::builder().label("Authorize").build();
        authorize_button.add_css_class("suggested-action");
        authorize_button.set_cursor_from_name(Some("pointer"));
        button_box.append(&authorize_button);
        auth_box.append(&button_box);

        stack.add_named(&select_box, Some("select"));
        stack.add_named(&auth_box, Some("authorize"));

        if skip_selection {
            stack.set_visible_child_name("authorize");
            window.set_title(Some(auth_title_str.as_ref()));
        } else {
            stack.set_visible_child_name("select");
            window.set_title(Some(select_title_str.as_ref()));
        }

        let stack_clone = stack.clone();
        let window_clone = window.clone();
        let auth_title_str_clone = auth_title_str.clone();
        let selected_index_clone2 = selected_index_clone.clone();
        let password_entry_clone = password_entry.clone();

        list_box.connect_row_activated({
            let app = app.clone();
            move |_, row| {
                let idx = row.index() as usize;
                selected_index_clone2.set(idx);

                if skip_password {
                    let mut stdout = std::io::stdout().lock();
                    let _ = stdout.write_all(&[0x02]);

                    let report = CborVec::from_serializable(
                        SelectionResponse {
                            index: idx,
                            passphrase: "",
                        },
                        std::mem::size_of::<SelectionResponse>(),
                    );

                    let _ = stdout.write_all(&report.into_inner());
                    let _ = stdout.flush();
                    app.quit();
                } else {
                    stack_clone.set_visible_child_name("authorize");
                    window_clone.set_title(Some(auth_title_str_clone.as_ref()));
                    password_entry_clone.grab_focus();
                }
            }
        });

        let submit_password = {
            let app = app.clone();
            let exit_code_clone = exit_code_clone.clone();
            let selected_index_clone = selected_index_clone.clone();
            let retry_count_clone = retry_count_clone.clone();
            let password_entry = password_entry.clone();
            let helper_label = helper_label.clone();

            move || {
                let mut pwd_str = password_entry.text().to_string();
                if pwd_str.is_empty() {
                    return;
                }

                let login = whoami::username().expect("Failed to get username");
                let mut client = match pam::Client::with_password("system-auth") {
                    Ok(c) => c,
                    Err(_) => return,
                };
                client.conversation_mut().set_credentials(login, &pwd_str);

                let retry = retry_count_clone.get();
                if client.authenticate().is_ok() || retry >= 3 {
                    let idx = selected_index_clone.get();
                    let mut stdout = std::io::stdout().lock();
                    let _ = stdout.write_all(&[0x02]);

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
                    exit_code_clone.set(ExitCode::SUCCESS);
                    app.quit();
                } else {
                    retry_count_clone.set(retry + 1);
                    helper_label.set_visible(true);
                    password_entry.set_text("");
                    pwd_str.zeroize();
                }
            }
        };

        authorize_button.connect_clicked({
            let submit = submit_password.clone();
            move |_| submit()
        });

        password_entry.connect_activate({
            let submit = submit_password.clone();
            move |_| submit()
        });

        window.set_child(Some(&stack));
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
            .join("../../../target/debug/passkeyd-gtk-select");

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
