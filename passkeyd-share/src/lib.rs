use ctap_types::webauthn::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity};
use iced::{
    Alignment, Background, Border, Color, Element, Font, Length, Theme, border,
    widget::{Row, button, column, image, row, text},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct OtherUI {
    pub user: PublicKeyCredentialUserEntity,
    pub site_icon: Option<bytes::Bytes>,
    pub user_icon: Option<bytes::Bytes>,
}

pub fn select_component<'a, T>(
    rp: &'a PublicKeyCredentialRpEntity,
    other_ui: &'a OtherUI,
    on_click_signal: Option<T>,
) -> Row<'a, T>
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
    };

    let final_image = user_profile.width(50).height(50).border_radius(100);
    let site_title = if let Some(title) = &rp.name {
        text(title.as_str())
    } else {
        text(rp.id.as_str())
    };

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
    };

    let user_info = row![column![site_title, user_display_name]];

    let selectable = button(
        row![final_image, user_info]
            .height(Length::Fill)
            .width(Length::Fill)
            .align_y(Alignment::Center)
            .spacing(24),
    )
    .style(|theme, status| button::text(theme, status))
    .on_press_maybe(on_click_signal);

    row![selectable]
}

pub fn title_bar_component<'a, T>(title: &'a str, close_signal: T) -> Element<'a, T>
where
    T: Clone + 'static,
{
    let title_icon = image("/usr/share/icons/hicolor/64x64/apps/passkeyd.png") // Example URL
        .width(24)
        .height(24);

    let title_text = text(title).size(20).font(Font {
        weight: iced::font::Weight::Semibold,
        ..Default::default()
    });

    let close_button = button("🗙")
        // .width(10)
        // .height(10)
        .style(|_theme: &Theme, _status| button::Style {
            background: Some(Background::Color(Color::from_rgb(0.625, 0.120, 0.95))),
            text_color: Color::from_rgb(0.531, 0.102, 0.808),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.4,
                radius: border::Radius::new(100),
            },
            ..Default::default()
        })
        .on_press(close_signal);

    row![title_icon, title_text, close_button]
        .spacing(12)
        .align_y(Alignment::Center)
        .into()
}