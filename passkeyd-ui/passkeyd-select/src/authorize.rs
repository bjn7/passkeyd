use iced::widget::{column, container, text, text_input};
use iced::{Alignment, Element, Length, Padding};
use passkeyd_abi::{component::title_bar_component, theme};
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
        let title_bar = title_bar_component(
            passkeyd_locale::translate!("ui.select.authorize.title_bar"),
            UserResponse::Deny,
        );
        let description = text(passkeyd_locale::translate!(
            "ui.select.authorize.description"
        ))
        .class(theme::TextClass::SecondaryText)
        .size(16);

        let helper_text = text(passkeyd_locale::translate!(
            "ui.select.authorize.helper_text"
        ))
        .class(theme::TextClass::ErrorText);

        let password = container(column![
            text_input(
                &passkeyd_locale::translate!("ui.select.authorize.password"),
                &self.password
            )
            .on_submit(UserResponse::Authorize)
            .secure(true)
            .on_input(UserResponse::ContentChanged)
            .padding(Padding::new(12.0))
            .width(354),
            self.is_invalid.then_some(helper_text)
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
