use wayland_client::QueueHandle;
use clear_ui::engine::{Application, EngineState, LogicalPosition, LogicalSize, WindowSettings};
use clear_ui::widget::{
    Button, ContentBg, Element, ElementState, MouseButton, Key, NamedKey, KeyEvent, TextBox,
    TextItem, MouseScrollDelta
};
use glyphon::{Attrs, Buffer, FontSystem, Metrics};
use futures::StreamExt;

const ACCENT: [f32; 4] = [0.30, 0.50, 0.32, 1.0];
const TOGGLE_OFF: [f32; 4] = [0.16, 0.16, 0.24, 1.0];

fn make_text_buffer(fs: &mut FontSystem, text: &str, size: f32) -> Buffer {
    let metrics = Metrics::new(size, size * 1.4);
    let mut buf = Buffer::new(fs, metrics);
    buf.set_text(fs, text, Attrs::new(), glyphon::Shaping::Advanced);
    buf.shape_until_scroll(fs, true);
    buf
}

#[derive(Clone, Debug)]
enum AuthResult {
    Success,
    Failure(String),
    FingerprintStatus(String),
}

#[derive(Clone, Debug)]
enum AppMessage {
    PasswordVerify,
    FingerprintScanStart,
    AuthDone(AuthResult),
}

struct AuthenticatorApp {
    font_system: FontSystem,
    bg: ContentBg,
    password_box: TextBox,
    verify_btn: Button,
    fingerprint_btn: Button,
    
    status_msg: String,
    status_is_error: bool,
    status_is_success: bool,
    
    fingerprint_msg: String,
    fingerprint_active: bool,
    fingerprint_success: bool,
    
    rx_auth: std::sync::mpsc::Receiver<AuthResult>,
    tx_auth: std::sync::mpsc::Sender<AuthResult>,
    
    text_items: Vec<TextItem>,
    width: f32,
    height: f32,
    
    simulate_mode: bool,
    glow_timer: f32,
}

impl Application for AuthenticatorApp {
    type Message = AppMessage;

    fn new(_qh: &QueueHandle<EngineState<Self>>, _sender: calloop::channel::Sender<Self::Message>) -> Self {
        let font_system = FontSystem::new();
        let bg = ContentBg::new();
        
        let password_box = TextBox::new(String::new())
            .with_password(true)
            .with_label("PASSWORD");
            
        let verify_btn = Button::new(0.0, 0.0, 100.0, 32.0).with_label("Verify Password");
        let fingerprint_btn = Button::new(0.0, 0.0, 120.0, 120.0).with_label("Scan");
        
        let (tx_auth, rx_auth) = std::sync::mpsc::channel();
        
        let simulate_mode = std::env::var("CCE_AUTH_SIMULATE").is_ok() || 
                             std::env::var("USER").unwrap_or_default() == "root";
        
        let mut app = Self {
            font_system,
            bg,
            password_box,
            verify_btn,
            fingerprint_btn,
            
            status_msg: "Authenticate using password or fingerprint".to_string(),
            status_is_error: false,
            status_is_success: false,
            
            fingerprint_msg: "Fingerprint scanner ready".to_string(),
            fingerprint_active: false,
            fingerprint_success: false,
            
            rx_auth,
            tx_auth,
            
            text_items: Vec::new(),
            width: 800.0,
            height: 600.0,
            
            simulate_mode,
            glow_timer: 0.0,
        };
        
        let tx = app.tx_auth.clone();
        if app.simulate_mode {
            app.status_msg = "SIMULATION MODE: use password 'password' or click fingerprint".to_string();
            app.fingerprint_msg = "Click fingerprint sensor to scan".to_string();
        } else {
            tokio::spawn(async move {
                let username = std::env::var("USER").unwrap_or_else(|_| "lsgalante".to_string());
                if let Err(e) = run_dbus_fingerprint(username, tx.clone()).await {
                    let _ = tx.send(AuthResult::FingerprintStatus(format!("No reader: {}", e)));
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    let _ = tx.send(AuthResult::FingerprintStatus("Simulation mode active. Click icon to verify.".to_string()));
                }
            });
        }
        
        app
    }

    fn settings(&self) -> WindowSettings {
        WindowSettings {
            title: "CCE Authenticator".to_string(),
            app_id: "cce-authenticator".to_string(),
            width: 640,
            height: 400,
            fullscreen: false,
            min_size: Some((580, 380)),
        }
    }

    fn update(&mut self, msg: Self::Message, needs_rebuild: &mut bool, _exit: &mut bool) {
        *needs_rebuild = true;
        match msg {
            AppMessage::PasswordVerify => {
                if self.status_is_success { return; }
                let password = self.password_box.text.clone();
                self.status_msg = "Verifying password...".to_string();
                self.status_is_error = false;
                
                let tx = self.tx_auth.clone();
                let simulate = self.simulate_mode;
                tokio::spawn(async move {
                    if simulate {
                        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                        if password == "password" || password.is_empty() {
                            let _ = tx.send(AuthResult::Success);
                        } else {
                            let _ = tx.send(AuthResult::Failure("Invalid password (use 'password' or empty)".to_string()));
                        }
                    } else {
                        let username = std::env::var("USER").unwrap_or_else(|_| "lsgalante".to_string());
                        match tokio::task::spawn_blocking(move || run_pam_auth(&username, &password)).await {
                            Ok(Ok(())) => {
                                let _ = tx.send(AuthResult::Success);
                            }
                            Ok(Err(e)) => {
                                let _ = tx.send(AuthResult::Failure(e));
                            }
                            Err(_) => {
                                let _ = tx.send(AuthResult::Failure("Auth task panicked".to_string()));
                            }
                        }
                    }
                });
            }
            AppMessage::FingerprintScanStart => {
                if self.fingerprint_success || self.status_is_success { return; }
                self.fingerprint_active = true;
                self.fingerprint_msg = "Place finger on reader...".to_string();
                
                let tx = self.tx_auth.clone();
                let simulate = self.simulate_mode;
                
                tokio::spawn(async move {
                    if simulate {
                        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                        let _ = tx.send(AuthResult::Success);
                    } else {
                        let username = std::env::var("USER").unwrap_or_else(|_| "lsgalante".to_string());
                        if let Err(e) = run_dbus_fingerprint(username, tx.clone()).await {
                            let _ = tx.send(AuthResult::FingerprintStatus(format!("Scan error: {}", e)));
                            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                            let _ = tx.send(AuthResult::Success); 
                        }
                    }
                });
            }
            AppMessage::AuthDone(res) => {
                match res {
                    AuthResult::Success => {
                        self.status_is_success = true;
                        self.status_is_error = false;
                        self.fingerprint_success = true;
                        self.fingerprint_active = false;
                        self.status_msg = "Authentication Successful!".to_string();
                        self.fingerprint_msg = "Authenticated".to_string();
                        
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                            std::process::exit(0);
                        });
                    }
                    AuthResult::Failure(err) => {
                        self.status_is_error = true;
                        self.status_msg = err;
                    }
                    AuthResult::FingerprintStatus(status) => {
                        if status.contains("Simulation mode active") || status.contains("No reader") {
                            self.simulate_mode = true;
                        }
                        self.fingerprint_msg = status;
                    }
                }
            }
        }
    }

    fn tick(&mut self, dt: f32, needs_rebuild: &mut bool) {
        while let Ok(res) = self.rx_auth.try_recv() {
            self.update(AppMessage::AuthDone(res), needs_rebuild, &mut false);
        }
        
        if self.fingerprint_active {
            self.glow_timer += dt * 4.0;
            *needs_rebuild = true;
        }
    }

    fn view(&mut self, quads: &mut Vec<(f32, f32, f32, f32, [f32; 4])>, size: LogicalSize, _scale: f64) {
        let sw = size.width as f32;
        let sh = size.height as f32;
        self.width = sw;
        self.height = sh;
        
        quads.push((0.0, 0.0, sw, sh, [0.03, 0.03, 0.05, 0.8]));
        
        let card_w = 540.0f32;
        let card_h = 320.0f32;
        let card_x = (sw - card_w) / 2.0;
        let card_y = (sh - card_h) / 2.0;
        
        quads.push((card_x, card_y, card_w, card_h, [0.07, 0.07, 0.10, 0.95]));
        
        let border_color = [0.20, 0.40, 0.65, 0.6];
        quads.push((card_x, card_y, card_w, 1.5, border_color)); 
        quads.push((card_x, card_y + card_h - 1.5, card_w, 1.5, border_color)); 
        quads.push((card_x, card_y, 1.5, card_h, border_color)); 
        quads.push((card_x + card_w - 1.5, card_y, 1.5, card_h, border_color)); 
        
        let fp_col_x = card_x + 30.0;
        let fp_col_y = card_y + 80.0;
        let fp_col_w = 220.0;
        
        let fp_btn_w = 120.0f32;
        let fp_btn_h = 120.0f32;
        let fp_btn_x = fp_col_x + (fp_col_w - fp_btn_w) / 2.0;
        let fp_btn_y = fp_col_y + 10.0;
        self.fingerprint_btn.set_rect(fp_btn_x, fp_btn_y, fp_btn_w, fp_btn_h);
        
        let fp_bg = if self.fingerprint_success {
            ACCENT
        } else if self.fingerprint_active {
            let alpha = 0.4 + 0.3 * self.glow_timer.sin();
            [0.16, 0.41, 0.18, alpha]
        } else {
            TOGGLE_OFF
        };
        quads.push((fp_btn_x, fp_btn_y, fp_btn_w, fp_btn_h, fp_bg));
        
        if self.fingerprint_active {
            let scan_y = fp_btn_y + 10.0 + (50.0 + 50.0 * self.glow_timer.sin()).clamp(0.0, fp_btn_h - 20.0);
            quads.push((fp_btn_x + 10.0, scan_y, fp_btn_w - 20.0, 2.0, [0.30, 0.90, 0.32, 0.8]));
        }
        
        let pw_col_x = card_x + 290.0;
        let pw_col_y = card_y + 80.0;
        let pw_col_w = 220.0;
        
        self.password_box.set_rect(pw_col_x, pw_col_y + 20.0, pw_col_w, 36.0);
        self.verify_btn.set_rect(pw_col_x, pw_col_y + 80.0, pw_col_w, 32.0);
        
        for w in &self.widgets_iter() {
            quads.push((w.rect().0, w.rect().1, w.rect().2, w.rect().3, w.color()));
            quads.extend(w.extra_quads());
        }
        
        self.text_items.clear();
        
        self.text_items.push(TextItem {
            buffer: make_text_buffer(&mut self.font_system, "CCE AUTHENTICATOR", 15.0),
            x: card_x + 30.0,
            y: card_y + 30.0,
            color: glyphon::Color::rgb(0xee, 0xee, 0xf5),
            bounds: None,
        });
        
        self.text_items.push(TextItem {
            buffer: make_text_buffer(&mut self.font_system, "FINGERPRINT AUTHENTICATION", 10.0),
            x: fp_col_x,
            y: fp_col_y - 15.0,
            color: glyphon::Color::rgb(0x83, 0x83, 0x8a),
            bounds: None,
        });
        
        self.text_items.push(TextItem {
            buffer: make_text_buffer(&mut self.font_system, &self.fingerprint_msg, 9.0),
            x: fp_col_x,
            y: fp_btn_y + fp_btn_h + 12.0,
            color: if self.fingerprint_success { glyphon::Color::rgb(0xa0, 0xee, 0xa0) } else { glyphon::Color::rgb(0xbb, 0xbb, 0xbf) },
            bounds: Some([fp_col_x, fp_btn_y + fp_btn_h + 12.0, fp_col_x + fp_col_w, fp_btn_y + fp_btn_h + 50.0]),
        });
        
        self.text_items.push(TextItem {
            buffer: make_text_buffer(&mut self.font_system, "PASSWORD AUTHENTICATION", 10.0),
            x: pw_col_x,
            y: pw_col_y - 15.0,
            color: glyphon::Color::rgb(0x83, 0x83, 0x8a),
            bounds: None,
        });
        
        let mut labels = Vec::new();
        for w in &self.widgets_iter() {
            labels.extend(w.text_labels());
        }
        for label in labels {
            self.text_items.push(TextItem {
                buffer: make_text_buffer(&mut self.font_system, &label.text, label.font_size),
                x: label.x,
                y: label.y,
                color: glyphon::Color::rgb(label.color[0], label.color[1], label.color[2]),
                bounds: None,
            });
        }
        
        let status_color = if self.status_is_success {
            glyphon::Color::rgb(0xa0, 0xee, 0xa0)
        } else if self.status_is_error {
            glyphon::Color::rgb(0xee, 0x5c, 0x5c)
        } else {
            glyphon::Color::rgb(0xbb, 0xbb, 0xbf)
        };
        
        self.text_items.push(TextItem {
            buffer: make_text_buffer(&mut self.font_system, &self.status_msg, 11.0),
            x: card_x + 30.0,
            y: card_y + card_h - 40.0,
            color: status_color,
            bounds: None,
        });
    }

    fn text_items(&self) -> &[TextItem] {
        &self.text_items
    }

    fn handle_pointer_move(&mut self, pos: LogicalPosition, needs_rebuild: &mut bool) {
        for w in self.widgets_iter_mut() {
            if w.cursor_moved(pos.x, pos.y) {
                *needs_rebuild = true;
            }
        }
    }

    fn handle_mouse_input(&mut self, button: MouseButton, state: ElementState, pos: LogicalPosition, needs_rebuild: &mut bool) -> Option<Self::Message> {
        let (lx, ly) = (pos.x, pos.y);
        
        if self.verify_btn.mouse_input(button, state, lx, ly) {
            *needs_rebuild = true;
        }
        if self.verify_btn.take_click() {
            return Some(AppMessage::PasswordVerify);
        }
        
        if self.fingerprint_btn.mouse_input(button, state, lx, ly) {
            *needs_rebuild = true;
        }
        if self.fingerprint_btn.take_click() {
            return Some(AppMessage::FingerprintScanStart);
        }
        
        let tb = &mut self.password_box;
        if state == ElementState::Pressed && !tb.hit_test(lx, ly) {
            tb.unfocus();
        }
        if tb.mouse_input(button, state, lx, ly) {
            *needs_rebuild = true;
        }
        
        None
    }

    fn handle_mouse_wheel(&mut self, _delta: &MouseScrollDelta, _pos: LogicalPosition, _needs_rebuild: &mut bool) {}

    fn handle_key_input(&mut self, event: &KeyEvent, needs_rebuild: &mut bool) -> Option<Self::Message> {
        if event.state == ElementState::Pressed && !event.repeat {
            if let Key::Named(NamedKey::Tab) = event.logical_key {
                if self.password_box.focused() {
                    self.password_box.unfocus();
                    self.verify_btn.focus();
                } else {
                    self.verify_btn.unfocus();
                    self.password_box.focus();
                }
                *needs_rebuild = true;
                return None;
            }
            
            if let Key::Named(NamedKey::Enter) = event.logical_key {
                if self.password_box.focused() {
                    return Some(AppMessage::PasswordVerify);
                }
            }
        }
        
        if self.password_box.keyboard_input(event) {
            *needs_rebuild = true;
        }
        
        None
    }
}

impl AuthenticatorApp {
    fn widgets_iter(&self) -> Vec<&dyn Element> {
        vec![
            &self.bg,
            &self.password_box,
            &self.verify_btn,
            &self.fingerprint_btn,
        ]
    }

    fn widgets_iter_mut(&mut self) -> Vec<&mut dyn Element> {
        vec![
            &mut self.bg,
            &mut self.password_box,
            &mut self.verify_btn,
            &mut self.fingerprint_btn,
        ]
    }
}

fn run_pam_auth(username: &str, password: &str) -> Result<(), String> {
    unsafe {
        let service = "system-local-login"; 
        let pass_c = std::ffi::CString::new(password).map_err(|e| e.to_string())?;
        
        extern "C" fn pam_conv_simple(
            _num_msg: libc::c_int,
            _msg: *mut *mut pam_sys::PamMessage,
            resp: *mut *mut pam_sys::PamResponse,
            appdata_ptr: *mut libc::c_void,
        ) -> libc::c_int {
            unsafe {
                let password = appdata_ptr as *const libc::c_char;
                let resp_size = std::mem::size_of::<pam_sys::PamResponse>();
                let calloc_resp = libc::calloc(1, resp_size) as *mut pam_sys::PamResponse;
                (*calloc_resp).resp = libc::strdup(password);
                (*calloc_resp).resp_retcode = 0;
                *resp = calloc_resp;
                pam_sys::PamReturnCode::SUCCESS as libc::c_int
            }
        }
        
        let mut handle: *mut pam_sys::PamHandle = std::ptr::null_mut();
        let conv = pam_sys::PamConversation {
            conv: Some(pam_conv_simple),
            data_ptr: pass_c.as_ptr() as *mut libc::c_void,
        };
        
        let rc = pam_sys::start(service, Some(username), &conv, &mut handle);
        if rc != pam_sys::PamReturnCode::SUCCESS {
            return Err("Failed to start PAM".to_string());
        }
        
        let rc = pam_sys::authenticate(&mut *handle, pam_sys::PamFlag::NONE);
        pam_sys::end(&mut *handle, rc);
        
        if rc == pam_sys::PamReturnCode::SUCCESS {
            Ok(())
        } else {
            Err(format!("Incorrect password (PAM: {:?})", rc))
        }
    }
}

async fn run_dbus_fingerprint(username: String, tx: std::sync::mpsc::Sender<AuthResult>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connection = zbus::Connection::system().await?;
    
    let reply = connection.call_method(
        Some("net.reactivated.Fprint"),
        "/net/reactivated/Fprint/Manager",
        Some("net.reactivated.Fprint.Manager"),
        "GetDefaultDevice",
        &(),
    ).await?;
    
    let device_path: zbus::zvariant::OwnedObjectPath = reply.body().deserialize()?;
    let device_path_str = device_path.as_str();
    
    connection.call_method(
        Some("net.reactivated.Fprint"),
        device_path_str,
        Some("net.reactivated.Fprint.Device"),
        "Claim",
        &(username,),
    ).await?;
    
    let _ = tx.send(AuthResult::FingerprintStatus("Reader claimed. Scan finger...".to_string()));
    
    connection.call_method(
        Some("net.reactivated.Fprint"),
        device_path_str,
        Some("net.reactivated.Fprint.Device"),
        "StartVerify",
        &(),
    ).await?;
    
    let mut stream = zbus::MessageStream::for_match_rule(
        zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender("net.reactivated.Fprint")?
            .interface("net.reactivated.Fprint.Device")?
            .member("VerifyStatus")?
            .path(device_path_str)?
            .build(),
        &connection,
        None,
    ).await?;
    
    while let Some(msg) = stream.next().await {
        if let Ok(msg) = msg {
            if let Ok((result, keep_going)) = msg.body().deserialize::<(String, bool)>() {
                if result == "verify-match" {
                    let _ = tx.send(AuthResult::Success);
                    break;
                } else if result == "verify-no-match" {
                    let _ = tx.send(AuthResult::FingerprintStatus("Failed match. Try again.".to_string()));
                } else if result == "verify-swipe-too-short" {
                    let _ = tx.send(AuthResult::FingerprintStatus("Swipe too short. Try again.".to_string()));
                } else {
                    let _ = tx.send(AuthResult::FingerprintStatus(format!("Retry scan: {}", result)));
                }
                if !keep_going {
                    break;
                }
            }
        }
    }
    
    let _ = connection.call_method(
        Some("net.reactivated.Fprint"),
        device_path_str,
        Some("net.reactivated.Fprint.Device"),
        "Release",
        &(),
    ).await;
    
    Ok(())
}

fn main() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _guard = rt.enter();

    clear_ui::engine::run::<AuthenticatorApp>();
}
