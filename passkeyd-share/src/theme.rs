use std::{env, fs, process::exit};

use iced::{
    Border, Color, Shadow, Vector,
    border::{self, Radius},
    theme::{self, Base},
    widget::{
        button, container,
        scrollable::{self, AutoScroll, Rail},
        text, text_input,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StylisedTheme {
    #[serde(with = "color_rgba")]
    pub background: Color,

    // #[serde(with = "color_rgba")]
    // pub title: Color,
    #[serde(with = "color_rgba")]
    pub primary_text: Color,

    #[serde(with = "color_rgba")]
    pub secondary_text: Color,

    #[serde(with = "color_rgba")]
    pub surface: Color,

    #[serde(with = "color_rgba")]
    pub surface_primary_text: Color,

    #[serde(with = "color_rgba")]
    pub surface_secondary_text: Color,

    #[serde(with = "color_rgba")]
    pub accent: Color,

    #[serde(with = "color_rgba")]
    pub scrollbar_track: Color,

    #[serde(with = "color_rgba")]
    pub scrollbar_thumb: Color,
}

impl Default for StylisedTheme {
    fn default() -> Self {
        let contents = fs::read_to_string("/usr/share/passkeyd/theme.conf").unwrap();
        match toml::from_str(&contents) {
            Ok(theme) => theme,
            Err(e) => {
                eprintln!("{e}");
                exit(2)
            }
        }
    }
}

impl Base for StylisedTheme {
    fn base(&self) -> theme::Style {
        theme::Style {
            background_color: self.background,
            text_color: self.primary_text,
        }
    }
    fn default(_preference: theme::Mode) -> Self {
        let homedir = env::home_dir().unwrap(); //let it panic.
        let config_path = homedir.join(".config/passkeyd/theme.conf");
        let contents = fs::read_to_string(config_path).unwrap();
        match toml::from_str(&contents) {
            Ok(theme) => theme,
            Err(_) => exit(2),
        }
    }
    fn mode(&self) -> theme::Mode {
        theme::Mode::None
    }
    fn palette(&self) -> Option<theme::Palette> {
        None
    }
    fn name(&self) -> &str {
        "Custom Theme"
    }
}

pub enum ButtonClass {
    Close,
    Approval,
    Component,
}

impl button::Catalog for StylisedTheme {
    type Class<'a> = ButtonClass;
    fn default<'a>() -> Self::Class<'a> {
        ButtonClass::Component
    }
    fn style(&self, class: &Self::Class<'_>, status: button::Status) -> button::Style {
        let (bg, text) = match status {
            button::Status::Active if matches!(class, ButtonClass::Close) => {
                (theme::palette::darken(self.accent, 0.06), self.accent)
            }
            button::Status::Active => (self.accent, self.primary_text),
            button::Status::Disabled => (
                theme::palette::lighten(self.accent, 0.3),
                theme::palette::lighten(self.accent, 0.3),
            ),
            button::Status::Hovered if matches!(class, ButtonClass::Close) => {
                (theme::palette::darken(self.accent, 0.12), self.accent)
            }
            button::Status::Hovered => (
                theme::palette::darken(self.accent, 0.3),
                theme::palette::darken(self.accent, 0.3),
            ),
            button::Status::Pressed => (
                theme::palette::darken(self.accent, 0.15),
                theme::palette::darken(self.accent, 0.06),
            ),
        };

        let (border_width, border_radius) = match class {
            ButtonClass::Approval => (0.0, 9.),
            ButtonClass::Close => (4., f32::MAX),
            ButtonClass::Component => (0.0, 0.0),
        };

        button::Style {
            background: if let ButtonClass::Component = class {
                None
            } else {
                // good first issue ig, use into instead
                Some(iced::Background::Color(bg))
            },
            text_color: text,
            border: iced::Border {
                color: theme::palette::lighten(self.accent, 0.1).scale_alpha(0.3),
                width: border_width,
                radius: Radius::new(border_radius),
            },
            ..Default::default()
        }
    }
}

pub enum TextClass {
    PrimaryText,                  // Title's text, approval button text
    SecondaryText,                // description's text
    ElevatedSurfacePrimaryText,   // Elevated surface text's site name
    ElevatedSurfaceSecondaryText, // Elevated surface text's site username
    ErrorText,                    // description's text
}

impl text::Catalog for StylisedTheme {
    type Class<'a> = TextClass;
    fn default<'a>() -> Self::Class<'a> {
        TextClass::PrimaryText
    }
    fn style(&self, item: &Self::Class<'_>) -> text::Style {
        let text_color = match item {
            TextClass::PrimaryText => self.primary_text,
            TextClass::SecondaryText => self.secondary_text,
            TextClass::ElevatedSurfacePrimaryText => self.surface_primary_text,
            TextClass::ElevatedSurfaceSecondaryText => self.surface_secondary_text,
            TextClass::ErrorText => Color::from_rgb8(180, 0, 0),
        };

        text::Style {
            color: Some(text_color),
        }
    }
}

impl scrollable::Catalog for StylisedTheme {
    type Class<'a> = ();
    fn default<'a>() -> Self::Class<'a> {
        ()
    }
    fn style(&self, _class: &Self::Class<'_>, status: scrollable::Status) -> scrollable::Style {
        let container = container::Style::default();
        let scrollbar = Rail {
            background: Some(self.scrollbar_track.into()),
            border: border::rounded(1),
            scroller: scrollable::Scroller {
                background: match status {
                    scrollable::Status::Hovered {
                        is_horizontal_scrollbar_hovered: _,
                        is_vertical_scrollbar_hovered: _,
                        is_horizontal_scrollbar_disabled: _,
                        is_vertical_scrollbar_disabled: _,
                    } => theme::palette::lighten(self.scrollbar_thumb, 0.1).into(),
                    scrollable::Status::Dragged {
                        is_horizontal_scrollbar_dragged: _,
                        is_vertical_scrollbar_dragged: _,
                        is_horizontal_scrollbar_disabled: _,
                        is_vertical_scrollbar_disabled: _,
                    } => theme::palette::lighten(self.scrollbar_thumb, 0.05).into(),
                    scrollable::Status::Active {
                        is_horizontal_scrollbar_disabled: _,
                        is_vertical_scrollbar_disabled: _,
                    } => theme::palette::lighten(self.scrollbar_thumb, 0.05).into(),
                },
                border: Border {
                    radius: Radius::new(2),
                    width: 0.,
                    color: Color::TRANSPARENT,
                },
            },
        };

        let auto_scroll = AutoScroll {
            background: self.scrollbar_thumb.into(),
            border: border::rounded(4).width(1).color(self.scrollbar_thumb),
            shadow: Shadow {
                color: theme::palette::darken(self.scrollbar_thumb.into(), 0.5),
                offset: Vector::ZERO,
                blur_radius: 0.,
            },
            icon: self.scrollbar_thumb.into(),
        };

        scrollable::Style {
            container,
            vertical_rail: scrollbar,
            horizontal_rail: scrollbar,
            gap: None,
            auto_scroll: auto_scroll,
        }
    }
}

impl text_input::Catalog for StylisedTheme {
    type Class<'a> = ();
    fn default<'a>() -> Self::Class<'a> {
        ()
    }
    fn style(&self, _class: &Self::Class<'_>, status: text_input::Status) -> text_input::Style {
        let (bg, text, border) = match status {
            text_input::Status::Active => (
                self.surface,
                self.primary_text,
                theme::palette::lighten(self.surface, 0.08).scale_alpha(0.75),
            ),
            text_input::Status::Disabled => (
                theme::palette::lighten(self.surface, 0.6),
                self.secondary_text,
                theme::palette::lighten(self.surface, 0.08).scale_alpha(0.75),
            ),
            text_input::Status::Focused { is_hovered: _ } => (
                self.surface,
                self.primary_text,
                theme::palette::lighten(self.surface, 0.08).scale_alpha(0.75),
            ),
            text_input::Status::Hovered => (
                theme::palette::darken(self.surface, 0.05).scale_alpha(0.9),
                self.primary_text,
                theme::palette::lighten(self.surface, 0.08).scale_alpha(0.75),
            ),
        };

        text_input::Style {
            background: bg.into(),
            border: Border {
                color: border,
                width: 2.,
                radius: Radius::new(4),
            },
            icon: self.surface_primary_text,
            placeholder: theme::palette::lighten(self.surface_primary_text, 0.4).scale_alpha(0.3),
            value: text,
            selection: theme::palette::lighten(self.accent, 0.2).scale_alpha(0.8),
        }
    }
}

pub enum ContainerClass {
    Elevated,
    UnElevated,
}
impl container::Catalog for StylisedTheme {
    type Class<'a> = ContainerClass;
    fn default<'a>() -> Self::Class<'a> {
        ContainerClass::UnElevated
    }
    fn style(&self, class: &Self::Class<'_>) -> container::Style {
        match class {
            ContainerClass::Elevated => container::Style {
                text_color: Some(self.surface_primary_text),
                background: Some(self.surface.into()),
                border: Border {
                    color: theme::palette::lighten(self.surface, 0.1).scale_alpha(0.8),
                    radius: Radius::new(6),
                    width: 1.,
                },
                shadow: Shadow {
                    color: theme::palette::lighten(self.surface, 0.1).scale_alpha(0.8),
                    offset: Vector::new(0., 0.),
                    blur_radius: 0.0,
                },
                ..Default::default()
            },
            ContainerClass::UnElevated => container::Style {
                text_color: None,
                background: None,
                border: Border {
                    color: theme::palette::lighten(self.surface, 0.4).scale_alpha(0.2),
                    radius: Radius::new(4),
                    width: 0.,
                },
                shadow: Shadow {
                    color: theme::palette::lighten(self.surface, 0.4).scale_alpha(0.3),
                    offset: Vector::new(0., 0.),
                    blur_radius: 0.,
                },
                ..Default::default()
            },
        }
    }
}

mod color_rgba {
    use iced::Color;
    use serde::{Deserialize, Deserializer, Serializer, de, ser::SerializeTuple};

    pub fn serialize<S>(color: &Color, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let rgba = color.into_rgba8();
        let mut seq = serializer.serialize_tuple(rgba.len())?;
        for c in rgba {
            seq.serialize_element(&c)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Color, D::Error>
    where
        D: Deserializer<'de>,
    {
        let rgba_bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if rgba_bytes.len() != 4 {
            return Err(de::Error::invalid_length(
                rgba_bytes.len(),
                &"a slice of length 4",
            ));
        }
        Ok(Color {
            r: rgba_bytes[0] as f32 / 255.0,
            g: rgba_bytes[1] as f32 / 255.0,
            b: rgba_bytes[2] as f32 / 255.0,
            a: rgba_bytes[3] as f32 / 255.0,
        })
    }
}

// impl Serialize for UserTheme {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         // self.accent.into_rgba8()
//         let mut state = serializer.serialize_struct("UserTheme", 10)?;
//         state.serialize_field("background", &self.background.into_rgba8())?;
//         state.serialize_field("title", &self.background.into_rgba8())?;
//         state.serialize_field("sub_text", &self.background.into_rgba8())?;
//         state.serialize_field("surface", &self.background.into_rgba8())?;
//         state.serialize_field("surface_text", &self.background.into_rgba8())?;
//         state.serialize_field("surface_sub_text", &self.background.into_rgba8())?;

//         state.serialize_field("primary_text", &self.background.into_rgba8())?;
//         state.serialize_field("accent", &self.background.into_rgba8())?;
//         state.serialize_field("scrollbar_track", &self.background.into_rgba8())?;
//         state.serialize_field("scrollbar_thumb", &self.background.into_rgba8())?;

//         state.end()
//     }
// }
