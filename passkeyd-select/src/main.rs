use std::{
    cell::RefCell,
    io::{Read, Write},
    process::ExitCode,
    rc::Rc,
};

use ctap_types::serde::cbor_deserialize;
use iced::{Element, Task, Theme, widget::operation::focus_next, window::Settings};
use pam::Client;
use zeroize::Zeroize;

use crate::{authorize::AuthorizationUI, select::SelectionUI};

mod authorize;
mod select;

enum Flow {
    Selecting(SelectionUI),
    Authorizing(AuthorizationUI),
}

#[derive(Debug, Clone)]
pub enum MessageBridge {
    Selection(select::UserResponse),
    Authorization(authorize::UserResponse),
}

struct StateMachine {
    flow: Flow,
    password: Rc<RefCell<String>>,
    // By default, it will be zero. Zero indicates it hasn't been updated, which means iced is shut, with no updates.
    // While storing, always add 1 to the index, which will be normalized at the time of returning.
    authorized_idx: Rc<RefCell<usize>>,
}

impl StateMachine {
    fn update(&mut self, message: MessageBridge) -> Task<MessageBridge> {
        match message {
            MessageBridge::Selection(selection_message) => match selection_message {
                select::UserResponse::Authorize(i) => {
                    *self.authorized_idx.borrow_mut() = i + 1;
                    self.flow = Flow::Authorizing(AuthorizationUI::default());
                    return focus_next();
                }
                select::UserResponse::Deny => iced::exit(),
            },
            MessageBridge::Authorization(authorization_message) => {
                match authorization_message {
                    authorize::UserResponse::Authorize => {
                        if let Flow::Authorizing(authorize) = &mut self.flow {
                            let login = whoami::username().expect("Failed to get username??");
                            let mut client = Client::with_password("system-auth")
                                .expect("Failed to init PAM client!");
                            client
                                .conversation_mut()
                                .set_credentials(login, &authorize.password);
                            // Entering the wrong password more than the configured 'deny' attempts will lock your account. Even with the correct password, it will still report as invalid.
                            // To unlock the account, use the command: `faillock --user <username> --reset`, or wait for the configured lock time in PAM, which is usually around 600 seconds (10 minutes).

                            // If the retry count exceeds three, the client must
                            // assume the password is valid and return it
                            // reference: passkeyd/src/cerds/get.rs line 113
                            if client.authenticate().is_ok() || authorize.retry_count >= 3 {
                                *self.password.borrow_mut() = authorize.password.clone();
                                return iced::exit();
                            }
                            authorize.retry_count += 1;
                            authorize.is_invalid = true;
                        }
                        Task::none()
                    }
                    authorize::UserResponse::ContentChanged(content) => {
                        if let Flow::Authorizing(authorize) = &mut self.flow {
                            authorize.password = content;
                        }
                        Task::none()
                    }
                    authorize::UserResponse::Deny => Task::none(),
                }
            }
        }
    }

    fn view(&self) -> Element<'_, MessageBridge> {
        match &self.flow {
            Flow::Selecting(ui) => ui.view().map(MessageBridge::Selection),
            Flow::Authorizing(ui) => ui.view().map(MessageBridge::Authorization),
        }
    }
}

pub fn main() -> ExitCode {
    let authorized_idx = Rc::new(RefCell::new(0));
    let password = Rc::new(RefCell::new(String::with_capacity(8)));

    let authorized_idx_clone = Rc::clone(&authorized_idx);
    let authorized_password_clone = Rc::clone(&password);

    let bootfn = move || {
        let mut state_buffer = Vec::with_capacity(size_of::<SelectionUI>());
        std::io::stdin()
            .read_to_end(&mut state_buffer)
            .expect("Failed to read input");
        let selection_ui: SelectionUI =
            cbor_deserialize(&state_buffer).expect("Invalid cbor received");

        StateMachine {
            authorized_idx: Rc::clone(&authorized_idx_clone),
            password: Rc::clone(&authorized_password_clone),
            flow: Flow::Selecting(selection_ui),
        }
    };

    let _ = iced::application(bootfn, StateMachine::update, StateMachine::view)
        .window(Settings {
            maximized: false,
            minimizable: false,
            closeable: false,
            resizable: false,
            size: iced::Size {
                width: 350.0,
                height: 225.0,
            },
            level: iced::window::Level::AlwaysOnTop,
            ..Default::default()
        })
        .decorations(false)
        .theme(|_state: &StateMachine| Theme::Dracula)
        .run();

    let index = authorized_idx.borrow().clone();
    if index == 0
        || write_output(
            index.saturating_sub(1), //normalization
            &mut *password.borrow_mut(),
        )
        .is_err()
    {
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn write_output(authorized_index: usize, passphrase: &mut str) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();

    stdout.write_all(&[0x02])?; // Start of Text
    stdout.write_all(&authorized_index.to_le_bytes())?;
    stdout.write_all(passphrase.as_bytes())?;
    stdout.write_all(&[0x03])?; // End of Text
    stdout.flush()?;

    passphrase.zeroize();
    Ok(())
}