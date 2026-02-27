use iced::widget::{column, container, text, text_input};
use iced::{Alignment, Element, Length, Padding};
use passkeyd_share::{theme, title_bar_component};
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
    pub fn view(&self) -> Element<'_, UserResponse, theme::StylisedTheme> {
        let title_bar = title_bar_component("Making sure it's you", UserResponse::Deny);
        let description = text("Enter your passphrase to authorize this passkey request")
            .class(theme::TextClass::SecondaryText)
            .size(16);

        let helper_text =
            text("Authentication failed, try again.").class(theme::TextClass::ErrorText);

        let password = container(column![
            text_input("Enter your passphrase", &self.password)
                .on_submit(UserResponse::Authorize)
                .secure(true)
                .on_input(UserResponse::ContentChanged)
                .padding(Padding::new(12.0))
                .width(354),
            self.is_invalid.then(|| helper_text)
        ])
        .height(Length::Fixed(110.))
        .width(Length::Fill)
        .align_y(Alignment::Center)
        .align_x(Alignment::Center);

        let body = column![description, password].height(Length::Fill);

        column![title_bar, body]
            .spacing(16)
            .padding([26, 26])
            .height(Length::Fill)
            .into()
    }
}
