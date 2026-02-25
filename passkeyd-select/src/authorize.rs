use iced::widget::{column, row, text, text_input};
use iced::{Alignment, Color, Element, Length};
use passkeyd_share::title_bar_component;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AuthorizationUI {
    pub password: String,
    pub is_invalid: bool,
    pub retry_count: usize,
}

#[derive(Debug, Clone)]
pub enum UserResponse {
    Deny,
    Authorize, //=> pressed enter,
    ContentChanged(String),
}

impl AuthorizationUI {
    // pub fn bootfn() -> (Self, Task<UserResponse>) {
    //     (AuthorizationUI::default(), focus_next())
    // }
    pub fn view(&self) -> Element<'_, UserResponse> {
        let title_bar = title_bar_component("Passkey login", UserResponse::Deny);
        let description = text("Making sure it's you")
            .color(Color::from_rgb(0.8, 0.8, 0.8))
            .height(Length::Shrink)
            .width(Length::Fill);

        let password = row![
            text_input("Enter your passphrase", &self.password)
                .on_submit(UserResponse::Authorize)
                .secure(true)
                .on_input(UserResponse::ContentChanged)
        ]
        .height(Length::Fill)
        .align_y(Alignment::Center)
        .padding([0, 10]);

        let helper_text =
            text("Authentication failed, try again.").color(Color::from_rgb(0.5, 0., 0.));

        let body = column![description, password, self.is_invalid.then(|| helper_text)]
            .padding([20, 0])
            .height(Length::Fill);

        column![title_bar, body]
            .padding([16, 16])
            .height(Length::Fill)
            .into()
    }
}
