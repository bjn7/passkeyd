use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use iced::widget::scrollable::Scrollbar;
use iced::widget::{Column, column, container, scrollable, text};
use iced::{Alignment, Element, Length, Padding};

use passkeyd_share::{OtherUI, theme, title_bar_component};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct SelectionUI {
    pub rp: PublicKeyCredentialRpEntity,
    pub other_uis: Vec<OtherUI>,
}

#[derive(Debug, Clone, Copy)]
pub enum UserResponse {
    Deny,
    Authorize(usize),
}

impl SelectionUI {
    pub fn view(&self) -> Element<'_, UserResponse, theme::StylisedTheme> {
        let title_bar = title_bar_component("Select Passkey", UserResponse::Deny);

        let description = text(format!(
            "The site {} is requesting to use a passkey.",
            self.rp.id.as_str(),
        ))
        .class(theme::TextClass::SecondaryText)
        .height(Length::Shrink)
        .width(Length::Fill);

        let users_component = self
            .other_uis
            .iter()
            .enumerate()
            .map(|(index, other_ui)| {
                passkeyd_share::user_component(
                    &self.rp,
                    other_ui,
                    Some(UserResponse::Authorize(index)),
                )
                .into()
            })
            .collect::<Column<'_, UserResponse, _>>()
            .spacing(4)
            .padding(Padding {
                top: 5.0,
                ..Default::default()
            });

        let scrollable_users = container(
            scrollable(
                container(users_component)
                    .align_x(Alignment::Center)
                    .align_y(Alignment::Center)
                    .width(Length::Fill),
            )
            .direction(scrollable::Direction::Vertical(Scrollbar::new()))
            .height(Length::Fill)
            .width(Length::Fill),
        )
        .width(Length::Fill)
        .padding(Padding {
            right: 24.,
            ..Default::default()
        });
        // let users = passkeyd_share::get_select_component(&self.rp, &self.other_uis, None);
        // let x = users_component.remove(0);
        // let y = users_component.remove(0);
        let spacing = 16;
        let body = column![description, scrollable_users]
            .spacing(18)
            .height(Length::Fill);
        // let approve = button("Authorize").on_press(UserResponse::Authorize);

        // let footer = row![Space::new().width(Length::Fill), approve]
        //     .width(Length::Fill)
        //     .padding([0, 30]);

        column![title_bar, body]
            .spacing(spacing)
            .padding([26, 26])
            .height(Length::Fill)
            .into()
    }
}
