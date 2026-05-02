// cheaply written passkey manager, held by duct tape
use std::process::{ExitCode, exit};
mod list_state;
mod tui;

fn main() -> ExitCode {
    passkeyd_locale::init_translations();
    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root {
        eprintln!(
            "{}",
            passkeyd_locale::translate!("manager.main.root_access_required")
        );
        exit(126);
    }

    let state = list_state::ListStateExt::new_from_file().unwrap();
    let mut app = tui::App::new(state);
    ratatui::run(|terminal| app.run(terminal)).unwrap();
    ExitCode::SUCCESS
}
