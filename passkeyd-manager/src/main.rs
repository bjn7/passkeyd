// cheaply written passkey manager, held by duct tape
use libc;
use std::process::{ExitCode, exit};

mod list_state;
mod tui;

fn main() -> ExitCode {
    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root {
        eprintln!("Are you running as root? Accessing the passkey list requires root privileges.");
        exit(126);
    }

    let state = list_state::ListStateExt::new_from_file().unwrap();
    let mut app = tui::App::new(state);
    ratatui::run(|terminal| app.run(terminal)).unwrap();
    ExitCode::SUCCESS
}
