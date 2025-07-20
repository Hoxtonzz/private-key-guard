use data_encoding::BASE64URL_NOPAD;
use ring::aead::{Aad, LessSafeKey, UnboundKey, Nonce, AES_256_GCM};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::fs;
use std::num::NonZeroU32;
use std::path::PathBuf;
use eframe::{egui, App};
use rfd::FileDialog;

const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const PBKDF2_ITER: u32 = 100_000;

pub struct AesApp {
    mode: Mode,
    password: String,
    input: String,
    output: String,
    selected_file: Option<PathBuf>,
}

#[derive(PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
}

impl Default for AesApp {
    fn default() -> Self {
        Self {
            mode: Mode::Encrypt,
            password: String::new(),
            input: String::new(),
            output: String::new(),
            selected_file: None,
        }
    }
}

fn configure_custom_fonts(ctx: &egui::Context) {
    use egui::{FontData, FontDefinitions, FontFamily};

    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert(
        "custom_english".to_string(),
        FontData::from_static(include_bytes!("/System/Library/Fonts/SFNS.ttf")),
    );

    fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "custom_english".to_owned());
    fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "custom_english".to_owned());

    ctx.set_fonts(fonts);
}

impl App for AesApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        configure_custom_fonts(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔐 AES-GCM Private Key Encryptor");

            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.mode, Mode::Encrypt, "Encrypt");
                ui.selectable_value(&mut self.mode, Mode::Decrypt, "Decrypt");
            });

            ui.separator();

            ui.label("🔑 Password:");
            ui.text_edit_singleline(&mut self.password);

            ui.horizontal(|ui| {
                if ui.button("📂 Choose File").clicked() {
                    if let Some(path) = FileDialog::new().pick_file() {
                        match fs::read_to_string(&path) {
                            Ok(content) => {
                                self.input = content;
                                self.selected_file = Some(path);
                            }
                            Err(e) => {
                                self.output = format!("Failed to read file: {}", e);
                            }
                        }
                    }
                }

                if let Some(path) = &self.selected_file {
                    ui.label(format!("Selected file: {}", path.display()));
                }
            });

            ui.label(if self.mode == Mode::Encrypt {
                "📥 Plaintext Private Key:"
            } else {
                "📥 Encrypted Base64 Content:"
            });
            ui.text_edit_multiline(&mut self.input);

            if ui.button(if self.mode == Mode::Encrypt { "🔒 Encrypt" } else { "🔓 Decrypt" }).clicked() {
                if self.mode == Mode::Encrypt {
                    self.output = match aes_encrypt(&self.input, &self.password) {
                        Ok(res) => res,
                        Err(e) => format!("Encryption failed: {}", e),
                    };
                } else {
                    match aes_decrypt(&self.input, &self.password) {
                        Ok(res) => {
                            if let Some(original_path) = &self.selected_file {
                                let mut new_path = original_path.clone();
                                new_path.set_extension("decrypted.pem");
                                match fs::write(&new_path, &res) {
                                    Ok(_) => {
                                        self.output = format!("Decryption successful. Saved to: {}", new_path.display());
                                    }
                                    Err(e) => {
                                        self.output = format!("Decrypted but failed to save: {}", e);
                                    }
                                }
                            } else {
                                self.output = res;
                            }
                        }
                        Err(e) => self.output = format!("Decryption failed: {}", e),
                    }
                }
            }

            ui.separator();
            ui.label("📤 Output:");
            ui.text_edit_multiline(&mut self.output);
        });
    }
}

fn aes_encrypt(plaintext: &str, password: &str) -> Result<String, String> {
    let rng = SystemRandom::new();

    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt).map_err(|_| "Failed to generate salt")?;

    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITER).unwrap(),
        &salt,
        password.as_bytes(),
        &mut key,
    );

    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| "Invalid key")?;
    let key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes).map_err(|_| "Failed to generate nonce")?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "Encryption failed")?;

    let mut combined = Vec::new();
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&in_out);

    Ok(BASE64URL_NOPAD.encode(&combined))
}

fn aes_decrypt(encoded: &str, password: &str) -> Result<String, String> {
    let data = BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| "Base64 decoding failed")?;
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err("Insufficient data length".into());
    }

    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let mut ciphertext = data[SALT_LEN + NONCE_LEN..].to_vec();

    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITER).unwrap(),
        salt,
        password.as_bytes(),
        &mut key,
    );

    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| "Invalid key")?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());

    let decrypted = key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| "Decryption failed")?;

    String::from_utf8(decrypted.to_vec()).map_err(|_| "UTF-8 decode error".into())
}

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "AES Private Key Tool",
        options,
        Box::new(|_| Box::new(AesApp::default())),
    ).unwrap();
}
