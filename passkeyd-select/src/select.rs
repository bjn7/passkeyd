use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use iced::widget::scrollable::Scrollbar;
use iced::widget::{column, scrollable, text};
use iced::{Color, Element, Length, Padding};

use passkeyd_share::{OtherUI, title_bar_component};
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
    pub fn view(&self) -> Element<'_, UserResponse> {
        let title_bar = title_bar_component("Passkey login", UserResponse::Deny);

        let description = text(format!(
            "The site {} is requesting to use a passkey.",
            self.rp.id.as_str(),
        ))
        .color(Color::from_rgb(0.8, 0.8, 0.8))
        .height(Length::Shrink)
        .width(Length::Fill);

        let users_component: Vec<Element<'_, UserResponse>> = self
            .other_uis
            .iter()
            .enumerate()
            .map(|(index, other_ui)| {
                passkeyd_share::select_component(
                    &self.rp,
                    other_ui,
                    Some(UserResponse::Authorize(index)),
                )
                .height(54)
                .into()
            })
            .collect::<Vec<_>>();

        let scrollable_users = scrollable(column(users_component).spacing(8).padding(Padding {
            top: 5.0,
            ..Default::default()
        }))
        .direction(scrollable::Direction::Vertical(Scrollbar::new()))
        .height(Length::Fill);

        // let users = passkeyd_share::get_select_component(&self.rp, &self.other_uis, None);
        // let x = users_component.remove(0);
        // let y = users_component.remove(0);
        let body = column![description, scrollable_users]
            .padding([20, 0])
            .height(Length::Fill);
        // let approve = button("Authorize").on_press(UserResponse::Authorize);

        // let footer = row![Space::new().width(Length::Fill), approve]
        //     .width(Length::Fill)
        //     .padding([0, 30]);

        column![title_bar, body]
            .padding([16, 16])
            .height(Length::Fill)
            .into()
    }
}
