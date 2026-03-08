use std::{fs, io};

use ctap_types::{serde::cbor_deserialize, webauthn::PublicKeyCredentialRpEntity};
use passkeyd_share::database::database_dir;
use passkeyd_share::database::layout::{Passkey, StoredPasskey};
use ratatui::{text::Text, widgets::ListState};

struct Database {
    rp: PublicKeyCredentialRpEntity,
    passkeys: Vec<Passkey>,
}

struct SelectedIndex {
    website: ListState,
    passkey: ListState,
}

enum ListType {
    WebsiteList,
    PasskeyList,
}

pub struct ListStateExt {
    database: Vec<Database>,
    index: SelectedIndex,
    list_type: ListType,
}

pub enum Selected {
    Passkey(Passkey),
    Website(PublicKeyCredentialRpEntity),
}

impl ListStateExt {
    fn clamp_index(selected: Option<usize>, len: usize) -> Option<usize> {
        (len > 0).then(|| selected.unwrap_or_default().min(len - 1))
    }

    fn selected_website_index(&self) -> Option<usize> {
        let index = self.index.website.selected()?;
        (index < self.database.len()).then_some(index)
    }

    fn selected_passkey_index(&self) -> Option<usize> {
        let website_index = self.selected_website_index()?;
        let passkey_index = self.index.passkey.selected()?;
        (passkey_index < self.database.get(website_index)?.passkeys.len()).then_some(passkey_index)
    }

    fn sync_website_selection(&mut self) {
        self.index.website.select(Self::clamp_index(
            self.index.website.selected(),
            self.database.len(),
        ));
    }

    fn sync_passkey_selection(&mut self) {
        let selected = self.selected_website_index().and_then(|index| {
            Self::clamp_index(
                self.index.passkey.selected(),
                self.database[index].passkeys.len(),
            )
        });
        self.index.passkey.select(selected);
    }

    pub fn new_from_file() -> Result<Self, io::Error> {
        let mut database = Vec::with_capacity(10);
        let database_dir = fs::read_dir(database_dir())?;
        'outer: for website_entry in database_dir {
            let website = website_entry?.path();
            let metadata_path = website.join("metadata");
            let metadata_bytes = fs::read(metadata_path)?;
            let rp: PublicKeyCredentialRpEntity = cbor_deserialize(&metadata_bytes).unwrap();
            let mut passkeys = Vec::new();

            for passkey_entry in website.read_dir()? {
                let passkey_entry = passkey_entry?;
                if passkey_entry.file_name() == "metadata" {
                    continue;
                }
                let passkey_bytes = fs::read(passkey_entry.path())?;
                let stored_passkey: StoredPasskey = cbor_deserialize(&passkey_bytes).unwrap();
                let mut passkey: Passkey = stored_passkey.try_into().unwrap();

                if passkey.credential_source.rp_id.as_str() == ".dummy" {
                    continue 'outer;
                }

                passkey.credential_source.other_ui.user_icon = None;
                passkey.credential_source.other_ui.site_icon = None;

                passkeys.push(passkey);
            }
            database.push(Database { rp, passkeys });
        }

        Ok(Self {
            index: SelectedIndex {
                website: if database.len() > 0 {
                    ListState::default().with_selected(Some(0))
                } else {
                    ListState::default()
                },
                passkey: ListState::default(),
            },
            database: database,
            list_type: ListType::WebsiteList,
        })
    }

    pub fn select_next(&mut self) {
        match self.list_type {
            ListType::PasskeyList => {
                let selected = self.selected_website_index().and_then(|index| {
                    let len = self.database[index].passkeys.len();
                    Self::clamp_index(
                        self.index
                            .passkey
                            .selected()
                            .map_or(Some(0), |current| Some(current.saturating_add(1))),
                        len,
                    )
                });
                self.index.passkey.select(selected);
            }
            ListType::WebsiteList => {
                let selected = Self::clamp_index(
                    self.index
                        .website
                        .selected()
                        .map_or(Some(0), |current| Some(current.saturating_add(1))),
                    self.database.len(),
                );
                self.index.website.select(selected);
            }
        };
    }

    pub fn select_previous(&mut self) {
        match self.list_type {
            ListType::PasskeyList => {
                let selected = self.selected_website_index().and_then(|index| {
                    let len = self.database[index].passkeys.len();
                    Self::clamp_index(
                        self.index
                            .passkey
                            .selected()
                            .map_or(Some(0), |current| Some(current.saturating_sub(1))),
                        len,
                    )
                });
                self.index.passkey.select(selected);
            }
            ListType::WebsiteList => {
                let selected = Self::clamp_index(
                    self.index
                        .website
                        .selected()
                        .map_or(Some(0), |current| Some(current.saturating_sub(1))),
                    self.database.len(),
                );
                self.index.website.select(selected);
            }
        };
    }

    pub fn remove(&mut self) -> Option<Selected> {
        match self.list_type {
            ListType::PasskeyList => {
                let website_index = self.selected_website_index()?;
                let passkey_index = self.selected_passkey_index()?;
                let passkey = self.database[website_index].passkeys.remove(passkey_index);
                self.sync_passkey_selection();
                Some(Selected::Passkey(passkey))
            }
            ListType::WebsiteList => {
                let current_index = self.selected_website_index()?;
                let db = self.database.remove(current_index);
                self.sync_website_selection();
                self.sync_passkey_selection();
                Some(Selected::Website(db.rp))
            }
        }
    }

    pub fn into_text(&self) -> Vec<Text<'static>> {
        // let x = self.database.get(self.index.website).unwrap();
        if self.database.len() == 0 {
            return vec![Text::from("Not Entry Found\0")];
        }

        match self.list_type {
            ListType::PasskeyList => {
                if let Some(db) = self
                    .selected_website_index()
                    .and_then(|index| self.database.get(index))
                {
                    return db
                        .passkeys
                        .iter()
                        .map(|passkey| {
                            if let Some(name) = &passkey.credential_source.other_ui.user.name {
                                Text::from(name.to_string())
                            } else if let Some(dname) =
                                &passkey.credential_source.other_ui.user.display_name
                            {
                                Text::from(dname.to_string())
                            } else {
                                Text::from(
                                    String::from_utf8_lossy(
                                        passkey.credential_source.other_ui.user.id.as_slice(),
                                    )
                                    .into_owned(),
                                )
                            }
                        })
                        .collect::<Vec<_>>();
                }
                Vec::new()
            }
            ListType::WebsiteList => {
                self.database
                    .iter()
                    .map(|db| {
                        // A site name is an arbitrary name which can be spoofed, but
                        // it is not insignificant.
                        if let Some(site_name) = &db.rp.name {
                            Text::from(site_name.to_string())
                        } else {
                            Text::from(db.rp.id.to_string())
                        }
                    })
                    .collect::<Vec<_>>()
            }
        }
    }

    pub fn switch_list(&mut self) {
        self.list_type = match self.list_type {
            ListType::PasskeyList => ListType::WebsiteList,
            ListType::WebsiteList => {
                self.sync_website_selection();
                self.sync_passkey_selection();
                ListType::PasskeyList
            }
        }
    }

    pub fn get_state_mut(&mut self) -> &mut ListState {
        match self.list_type {
            ListType::PasskeyList => &mut self.index.passkey,
            ListType::WebsiteList => &mut self.index.website,
        }
    }
}
