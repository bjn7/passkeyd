use crate::database::layout::OtherUI;
use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use iced::{
    Alignment, Element, Font, Length,
    widget::{Button, button, column, container, image, row, text},
};

use super::theme;

pub fn user_component<'a, T>(
    rp: &'a PublicKeyCredentialRpEntity,
    other_ui: &'a OtherUI,
    on_click_signal: Option<T>,
) -> Button<'a, T, theme::StylisedTheme>
where
    T: 'static + Clone,
{
    let user_profile = if let Some(uicon) = &other_ui.user_icon {
        image(image::Handle::from_bytes(uicon.clone()))
    } else if let Some(sicon) = &other_ui.site_icon {
        image(image::Handle::from_bytes(sicon.clone()))
    } else {
        image(image::Handle::from_path(
            "/usr/share/icons/hicolor/64x64/apps/passkeyd.png",
        ))
    }
    .width(42)
    .height(42)
    .border_radius(f32::MAX);

    let site_title = if let Some(title) = &rp.name {
        text(title.as_str())
    } else {
        text(rp.id.as_str())
    }
    .size(16)
    .class(theme::TextClass::ElevatedSurfacePrimaryText);

    let user_display_name = if let Some(dname) = &other_ui.user.display_name {
        text(dname.as_str())
    } else if let Some(name) = &other_ui.user.name {
        text(name.as_str())
    } else {
        text(
            other_ui
                .user
                .id
                .as_slice()
                .iter()
                .map(|x| x.to_string())
                .collect::<String>(),
        )
    }
    .size(16)
    .class(theme::TextClass::ElevatedSurfaceSecondaryText);

    let user_info = container(column![site_title, user_display_name].padding([10, 0]))
        .align_y(Alignment::Center);
    let full = button(
        container(
            row![user_profile, user_info]
                .spacing(16)
                .align_y(Alignment::Center)
                .padding([0, 16]),
        )
        .class(theme::ContainerClass::Elevated)
        .width(Length::Fixed(282.))
        .height(Length::Fixed(60.)),
    )
    .on_press_maybe(on_click_signal);
    // let selectable = button(container(row![row![user_profile].align_y(Alignment::Center), user_info].spacing(18)).align_x(Alignment::Center).align_y(Alignment::Center).class(theme::ContainerClass::Elevated)).width(Length::Fill).on_press_maybe(on_click_signal);
    full
}

pub fn title_bar_component<'a, T>(
    title: &'a str,
    close_signal: T,
) -> Element<'a, T, theme::StylisedTheme>
where
    T: Clone + 'static,
{
    let title_text = text(title)
        .size(20)
        .font(Font {
            weight: iced::font::Weight::ExtraBold,
            ..Default::default()
        })
        .width(Length::Fill);

    let close_button = button(
        text("🗙")
            .align_y(Alignment::Center)
            .align_x(Alignment::Center)
            .size(16)
            .line_height(1.)
            .height(Length::Fill)
            .width(Length::Fill),
    )
    .width(34)
    .height(34)
    .class(theme::ButtonClass::Close)
    .on_press(close_signal);

    row![title_text, close_button]
        .spacing(12)
        .align_y(Alignment::Center)
        .width(Length::Fill)
        .into()
}
