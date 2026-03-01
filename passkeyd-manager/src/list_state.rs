use std::{fs, io};

use ctap_types::{serde::cbor_deserialize, webauthn::PublicKeyCredentialRpEntity};
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
    pub fn new_from_file() -> Result<Self, io::Error> {
        let mut database = Vec::with_capacity(10);
        let database_dir = fs::read_dir("/var/lib/passkeyd/database")?;
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
                let current_index = self.index.passkey.selected().unwrap_or_default();
                let selected = self
                    .database
                    .get(current_index)
                    .map(|db| std::cmp::min(db.passkeys.len().saturating_sub(1), current_index + 1));
                self.index.passkey.select(selected);
            }
            ListType::WebsiteList => {
                let current_index = self.index.website.selected().unwrap_or_default();
                self.index.website.select(Some(std::cmp::min(
                    self.database.len().saturating_sub(1),
                    current_index + 1,
                )));
            }
        };
    }

    pub fn select_previous(&mut self) {
        match self.list_type {
            ListType::PasskeyList => self.index.passkey.select_previous(),
            ListType::WebsiteList => self.index.website.select_previous(),
        };
    }

    pub fn remove(&mut self) -> Option<Selected> {
        match self.list_type {
            ListType::PasskeyList => self
                .database
                .get_mut(self.index.website.offset())
                .map(|db| {
                    let pass = db.passkeys.remove(self.index.passkey.offset());
                    Selected::Passkey(pass)
                }),
            ListType::WebsiteList => {
                let current_index = self.index.website.selected().unwrap_or_default();
                if self.database.len() - 1 > current_index {
                    let db = self.database.remove(current_index);
                    Some(Selected::Website(db.rp))
                } else {
                    None
                }
            }
        }
    }

    pub fn into_text(&self) -> Vec<Text<'_>> {
        // let x = self.database.get(self.index.website).unwrap();
        if self.database.len() == 0 {
            return vec![Text::from("Not Entry Found\0")];
        }

        match self.list_type {
            ListType::PasskeyList => {
                if let Some(db) = self
                    .database
                    .get(self.index.website.selected().unwrap_or_default())
                {
                    return db
                        .passkeys
                        .iter()
                        .map(|passkey| {
                            if let Some(name) = &passkey.credential_source.other_ui.user.name {
                                Text::from(name.as_str())
                            } else if let Some(dname) =
                                &passkey.credential_source.other_ui.user.display_name
                            {
                                Text::from(dname.as_str())
                            } else {
                                Text::from(String::from_utf8_lossy(
                                    passkey.credential_source.other_ui.user.id.as_slice(),
                                ))
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
                            Text::from(site_name.as_str())
                        } else {
                            Text::from(db.rp.id.as_str())
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
                self.index.passkey = self.index.passkey.with_selected(Some(0));
                ListType::PasskeyList
            }
        }
    }
    pub fn get_state(&self) -> ListState {
        match self.list_type {
            ListType::PasskeyList => self.index.passkey,
            ListType::WebsiteList => self.index.website,
        }
    }
}
