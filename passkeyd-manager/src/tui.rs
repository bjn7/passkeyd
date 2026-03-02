use std::io;

use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use passkeyd_share::{
    config::{self, Config},
    database::{remove_passkey, remove_table},
    utils::spawn_ui,
};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyEventKind},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, List},
};
use serde::Serialize;

use crate::list_state::{ListStateExt, Selected};

pub struct App {
    list: ListStateExt,
    exit: bool,
    config: Config,
}

impl App {
    pub fn new(state: ListStateExt) -> Self {
        Self {
            list: state,
            exit: false,
            config: config::Config::initialize().unwrap(),
        }
    }
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        while !self.exit {
            terminal.draw(|frame| self.draw(frame))?;
            self.handle_events()?;
        }
        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        let layout_area = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![Constraint::Percentage(85), Constraint::Percentage(15)])
            .split(frame.area());

        let border = Block::new()
            .title("Passkeyd Manager")
            .style(
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::LightBlue));

        let list: List<'_> = List::new(self.list.into_text())
            .block(border)
            .direction(ratatui::widgets::ListDirection::TopToBottom)
            .style(Style::default().fg(Color::White))
            .highlight_style(
                Style::default()
                    .bg(Color::White)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(" > ")
            .repeat_highlight_symbol(false);

        frame.render_stateful_widget(list, layout_area[0], &mut self.list.get_state());
    }

    fn handle_events(&mut self) -> io::Result<()> {
        match event::read()? {
            Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                match key_event.code {
                    event::KeyCode::Char('c')
                        if key_event.modifiers.contains(event::KeyModifiers::CONTROL) =>
                    {
                        self.exit = true
                    }
                    event::KeyCode::Enter => self.list.switch_list(),
                    event::KeyCode::Esc => self.list.switch_list(),
                    event::KeyCode::Delete => {
                        let confirmation = SelectionUIState {
                            title: "Confirm this action?".into(),
                            description: "Are you sure? Authorize this request to prove you didn't press the delete key by accident.".into(),
                            button: "authorize".into()
                        };
                        let res = spawn_ui(
                            &self.config,
                            passkeyd_share::utils::UI::KeySelection,
                            confirmation,
                        )
                        .wait()
                        .unwrap();

                        if res.success()
                            && let Some(selected) = self.list.remove()
                        {
                            match selected {
                                Selected::Website(website) => remove_table(&website),
                                Selected::Passkey(passkey) => {
                                    let mock_rp = PublicKeyCredentialRpEntity {
                                        icon: None,
                                        id: passkey.credential_source.rp_id.clone(),
                                        name: None,
                                    };
                                    remove_passkey(&mock_rp, &passkey.credential_source.id);
                                }
                            }
                        }
                    }
                    event::KeyCode::Up => self.list.select_previous(),
                    event::KeyCode::Down => self.list.select_next(),
                    _ => {}
                }
            }
            _ => {}
        };
        Ok(())
    }
}

#[derive(Serialize)]
pub struct SelectionUIState {
    pub description: String,
    pub title: String,
    pub button: String,
}
