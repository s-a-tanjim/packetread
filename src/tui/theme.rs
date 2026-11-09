use crate::decode::Protocol;
use ratatui::style::Color;

#[derive(Clone, Copy)]
pub struct Theme {
    pub name: &'static str,
    pub bg: Color,
    pub panel: Color,
    pub text: Color,
    pub muted: Color,
    pub cyan: Color,
    pub green: Color,
    pub purple: Color,
    pub yellow: Color,
    pub red: Color,
}

impl Theme {
    pub fn named(name: &str) -> Self {
        use Color::{Indexed, Rgb};
        match name {
            "indexed" => Self {
                name: "indexed",
                bg: Indexed(234),
                panel: Indexed(235),
                text: Indexed(255),
                muted: Indexed(245),
                cyan: Indexed(81),
                green: Indexed(114),
                purple: Indexed(177),
                yellow: Indexed(221),
                red: Indexed(203),
            },
            "contrast" => Self {
                name: "contrast",
                bg: Color::Black,
                panel: Color::Black,
                text: Color::White,
                muted: Color::Gray,
                cyan: Color::Cyan,
                green: Color::Green,
                purple: Color::Magenta,
                yellow: Color::Yellow,
                red: Color::LightRed,
            },
            _ => Self {
                name: "vivid",
                bg: Rgb(12, 17, 26),
                panel: Rgb(18, 25, 37),
                text: Rgb(221, 230, 244),
                muted: Rgb(137, 156, 184),
                cyan: Rgb(93, 218, 245),
                green: Rgb(150, 226, 138),
                purple: Rgb(198, 159, 255),
                yellow: Rgb(250, 206, 111),
                red: Rgb(255, 120, 139),
            },
        }
    }
    pub fn next(self) -> Self {
        Self::named(match self.name {
            "vivid" => "indexed",
            "indexed" => "contrast",
            _ => "vivid",
        })
    }
    pub fn protocol(self, protocol: Protocol) -> Color {
        match protocol {
            Protocol::Tcp => self.cyan,
            Protocol::Udp => self.purple,
            Protocol::Dns => self.green,
            Protocol::Arp => self.yellow,
            Protocol::Icmp => self.red,
            _ => self.muted,
        }
    }
}
