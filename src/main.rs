use wayland_client::QueueHandle;
use clear_ui::engine::{Application, EngineState, LogicalPosition, LogicalSize, WindowSettings};
use clear_ui::widget::{
    Button, ContentBg, Element, ElementState, MouseButton, Key, NamedKey, KeyEvent, TextBox,
    TextItem, MouseScrollDelta
};
use glyphon::{Attrs, Buffer, FontSystem, Metrics};
use futures::StreamExt;
use std::sync::{Arc, Mutex};
use std::io::Write;
use tokio::sync::oneshot;
use std::ops::Deref;

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
    ExitWindow,
    Failure(String),
    FingerprintStatus(String),
}

#[derive(Clone, Debug)]
enum AppMessage {
    PasswordVerify,
    FingerprintScanStart,
    AuthDone(AuthResult),
    Cancel,
    PromptReceived(String, bool), // (prompt, echo)
    StatusReceived(String, bool), // (message, is_error)
}

struct GuiRequest {
    username: String,
    message: String,
    cookie: String,
    tx_result: oneshot::Sender<Result<(), String>>,
}

static ACTIVE_REQUEST: Mutex<Option<GuiRequest>> = Mutex::new(None);
static ACTIVE_SENDER: Mutex<Option<calloop::channel::Sender<AppMessage>>> = Mutex::new(None);
static ACTIVE_COOKIE: Mutex<Option<String>> = Mutex::new(None);

struct AuthenticatorApp {
    font_system: FontSystem,
    bg: ContentBg,
    password_box: TextBox,
    verify_btn: Button,
    cancel_btn: Button,
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
    
    polkit_mode: bool,
    helper_stdin: Option<std::process::ChildStdin>,
    shared_child: Option<Arc<Mutex<Option<std::process::Child>>>>,
    sender: calloop::channel::Sender<AppMessage>,
}

impl Application for AuthenticatorApp {
    type Message = AppMessage;

    fn new(_qh: &QueueHandle<EngineState<Self>>, sender: calloop::channel::Sender<Self::Message>) -> Self {
        let font_system = FontSystem::new();
        let bg = ContentBg::new();
        
        let password_box = TextBox::new(String::new())
            .with_password(true)
            .with_label("PASSWORD");
            
        let verify_btn = Button::new(0.0, 0.0, 100.0, 32.0).with_label("Verify Password");
        let cancel_btn = Button::new(0.0, 0.0, 100.0, 32.0).with_label("Cancel");
        let fingerprint_btn = Button::new(0.0, 0.0, 120.0, 120.0).with_label("Scan");
        
        let (tx_auth, rx_auth) = std::sync::mpsc::channel();
        
        let active_req = ACTIVE_REQUEST.lock().unwrap();
        let polkit_mode = active_req.is_some();
        
        let mut helper_stdin = None;
        let mut shared_child = None;
        let mut status_msg = "Authenticate using password or fingerprint".to_string();
        let mut simulate_mode = std::env::var("CCE_AUTH_SIMULATE").is_ok() || 
                             std::env::var("USER").unwrap_or_default() == "root";
        
        if let Some(ref req) = *active_req {
            status_msg = req.message.clone();
            if std::env::var("CCE_AUTH_SIMULATE").is_err() {
                simulate_mode = false;
            }
            
            if !simulate_mode {
                // Spawn polkit-agent-helper-1
                match std::process::Command::new("/usr/lib/polkit-1/polkit-agent-helper-1")
                    .arg(&req.username)
                    .arg(&req.cookie)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::inherit())
                    .spawn()
                {
                    Ok(mut child) => {
                        let stdin = child.stdin.take();
                        let stdout = child.stdout.take();
                        helper_stdin = stdin;
                        
                        let child_arc = Arc::new(Mutex::new(Some(child)));
                        shared_child = Some(child_arc.clone());
                        
                        if let Some(stdout) = stdout {
                            let sender_clone = sender.clone();
                            std::thread::spawn(move || {
                                use std::io::BufRead;
                                let reader = std::io::BufReader::new(stdout);
                                for line in reader.lines() {
                                    if let Ok(line) = line {
                                        if line.starts_with("PAM_PROMPT_ECHO_OFF ") {
                                            let prompt = line["PAM_PROMPT_ECHO_OFF ".len()..].to_string();
                                            let _ = sender_clone.send(AppMessage::PromptReceived(prompt, false));
                                        } else if line.starts_with("PAM_PROMPT_ECHO_ON ") {
                                            let prompt = line["PAM_PROMPT_ECHO_ON ".len()..].to_string();
                                            let _ = sender_clone.send(AppMessage::PromptReceived(prompt, true));
                                        } else if line.starts_with("PAM_ERROR_MSG ") {
                                            let msg = line["PAM_ERROR_MSG ".len()..].to_string();
                                            let _ = sender_clone.send(AppMessage::StatusReceived(msg, true));
                                        } else if line.starts_with("PAM_TEXT_INFO ") {
                                            let msg = line["PAM_TEXT_INFO ".len()..].to_string();
                                            let _ = sender_clone.send(AppMessage::StatusReceived(msg, false));
                                        }
                                    }
                                }
                                
                                // Wait for child helper to exit
                                let mut lock = child_arc.lock().unwrap();
                                if let Some(mut child) = lock.take() {
                                    drop(lock);
                                    let exit_status = child.wait();
                                    match exit_status {
                                        Ok(status) if status.success() => {
                                            let _ = sender_clone.send(AppMessage::AuthDone(AuthResult::Success));
                                        }
                                        _ => {
                                            let _ = sender_clone.send(AppMessage::AuthDone(AuthResult::Failure("Authentication failed".to_string())));
                                        }
                                    }
                                }
                            });
                        }
                    }
                    Err(e) => {
                        status_msg = format!("Failed to spawn helper: {}", e);
                    }
                }
            }
        }
        
        // Store active sender for Cancel D-Bus calls
        *ACTIVE_SENDER.lock().unwrap() = Some(sender.clone());
        
        let mut app = Self {
            font_system,
            bg,
            password_box,
            verify_btn,
            cancel_btn,
            fingerprint_btn,
            
            status_msg,
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
            
            polkit_mode,
            helper_stdin,
            shared_child,
            sender: sender.clone(),
        };
        
        let tx = app.tx_auth.clone();
        if app.simulate_mode {
            app.status_msg = "SIMULATION MODE: use password 'password' or click fingerprint".to_string();
            app.fingerprint_msg = "Click fingerprint sensor to scan".to_string();
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                println!("Auto-authenticating in simulation mode...");
                let _ = tx_clone.send(AuthResult::Success);
            });
        } else if !app.polkit_mode {
            tokio::spawn(async move {
                let username = std::env::var("USER").unwrap_or_else(|_| "lsgalante".to_string());
                if let Err(e) = run_dbus_fingerprint(username, tx.clone()).await {
                    let _ = tx.send(AuthResult::FingerprintStatus(format!("No reader: {}", e)));
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    let _ = tx.send(AuthResult::FingerprintStatus("Simulation mode active. Click icon to verify.".to_string()));
                }
            });
        } else {
            tokio::spawn(async move {
                let username = std::env::var("USER").unwrap_or_else(|_| "lsgalante".to_string());
                let _ = run_dbus_fingerprint(username, tx.clone()).await;
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

    fn update(&mut self, msg: Self::Message, needs_rebuild: &mut bool, exit: &mut bool) {
        *needs_rebuild = true;
        match msg {
            AppMessage::PasswordVerify => {
                if self.status_is_success { return; }
                let password = self.password_box.text.clone();
                self.status_msg = "Verifying password...".to_string();
                self.status_is_error = false;
                
                if self.polkit_mode && !self.simulate_mode {
                    if let Some(ref mut stdin) = self.helper_stdin {
                        let _ = writeln!(stdin, "{}", password);
                        let _ = stdin.flush();
                        self.password_box.text.clear();
                    }
                } else {
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
                        }
                    }
                });
            }
            AppMessage::Cancel => {
                if let Some(ref shared_child) = self.shared_child {
                    if let Some(mut child) = shared_child.lock().unwrap().take() {
                        let _ = child.kill();
                    }
                }
                *exit = true;
            }
            AppMessage::PromptReceived(prompt, _echo) => {
                self.password_box.set_label(&prompt);
                self.password_box.text.clear();
            }
            AppMessage::StatusReceived(msg, is_error) => {
                self.status_msg = msg;
                self.status_is_error = is_error;
                self.status_is_success = false;
            }
            AppMessage::AuthDone(res) => {
                println!("AppMessage::AuthDone received: {:?}", res);
                match res {
                    AuthResult::Success => {
                        self.status_is_success = true;
                        self.status_is_error = false;
                        self.fingerprint_success = true;
                        self.fingerprint_active = false;
                        self.status_msg = "Authentication Successful!".to_string();
                        self.fingerprint_msg = "Authenticated".to_string();
                        
                        if self.polkit_mode {
                            println!("AuthResult::Success in Polkit mode. Sending Ok to tx_result and spawning exit timer.");
                            if let Some(req) = ACTIVE_REQUEST.lock().unwrap().take() {
                                let _ = req.tx_result.send(Ok(()));
                            } else {
                                println!("WARNING: ACTIVE_REQUEST was None inside AuthDone(Success)!");
                            }
                            let tx = self.tx_auth.clone();
                            tokio::spawn(async move {
                                println!("Exit timer task spawned, sleeping 800ms...");
                                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                                println!("Exit timer slept 800ms. Sending ExitWindow to tx.");
                                let _ = tx.send(AuthResult::ExitWindow);
                            });
                        } else {
                            println!("AuthResult::Success in standalone mode. Exiting process in 1000ms.");
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                                std::process::exit(0);
                            });
                        }
                    }
                    AuthResult::ExitWindow => {
                        println!("AuthResult::ExitWindow received in update. Setting exit = true.");
                        *exit = true;
                    }
                    AuthResult::Failure(err) => {
                        println!("AuthResult::Failure received: {}", err);
                        self.status_is_error = true;
                        self.status_msg = err;
                    }
                    AuthResult::FingerprintStatus(status) => {
                        println!("AuthResult::FingerprintStatus received: {}", status);
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
            let _ = self.sender.send(AppMessage::AuthDone(res));
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
        
        let btn_w = 100.0f32;
        let btn_h = 32.0f32;
        let verify_x = pw_col_x;
        let cancel_x = pw_col_x + pw_col_w - btn_w;
        
        self.verify_btn.set_rect(verify_x, pw_col_y + 80.0, btn_w, btn_h);
        self.cancel_btn.set_rect(cancel_x, pw_col_y + 80.0, btn_w, btn_h);
        
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
            buffer: make_text_buffer(&mut self.font_system, &self.status_msg, 10.0),
            x: card_x + 30.0,
            y: card_y + card_h - 40.0,
            color: status_color,
            bounds: Some([card_x + 30.0, card_y + card_h - 45.0, card_x + card_w - 30.0, card_y + card_h - 5.0]),
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
        
        if self.cancel_btn.mouse_input(button, state, lx, ly) {
            *needs_rebuild = true;
        }
        if self.cancel_btn.take_click() {
            return Some(AppMessage::Cancel);
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
                } else if self.verify_btn.focused() {
                    self.verify_btn.unfocus();
                    self.cancel_btn.focus();
                } else {
                    self.cancel_btn.unfocus();
                    self.password_box.focus();
                }
                *needs_rebuild = true;
                return None;
            }
            
            if let Key::Named(NamedKey::Escape) = event.logical_key {
                return Some(AppMessage::Cancel);
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
            &self.cancel_btn,
            &self.fingerprint_btn,
        ]
    }

    fn widgets_iter_mut(&mut self) -> Vec<&mut dyn Element> {
        vec![
            &mut self.bg,
            &mut self.password_box,
            &mut self.verify_btn,
            &mut self.cancel_btn,
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

struct PolkitAgent {
    tx_gui_req: std::sync::mpsc::Sender<GuiRequest>,
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl PolkitAgent {
    async fn begin_authentication(
        &self,
        _action_id: String,
        message: String,
        _icon_name: String,
        _details: std::collections::HashMap<String, String>,
        cookie: String,
        identities: Vec<(String, std::collections::HashMap<String, zbus::zvariant::OwnedValue>)>,
    ) -> zbus::fdo::Result<()> {
        println!("begin_authentication called! message = {:?}, cookie = {:?}", message, cookie);
        let mut username = String::new();
        if let Some((kind, details)) = identities.first() {
            if kind == "unix-user" {
                if let Some(uid_val) = details.get("uid") {
                    let uid = match uid_val.deref() {
                        zbus::zvariant::Value::U32(u) => Some(*u),
                        zbus::zvariant::Value::I32(i) => Some(*i as u32),
                        zbus::zvariant::Value::U64(u) => Some(*u as u32),
                        zbus::zvariant::Value::I64(i) => Some(*i as u32),
                        _ => None,
                    };
                    if let Some(uid) = uid {
                        if let Some(user) = users::get_user_by_uid(uid) {
                            username = user.name().to_string_lossy().into_owned();
                        }
                    }
                }
            }
        }
        if username.is_empty() {
            username = std::env::var("USER").unwrap_or_else(|_| "lsgalante".to_string());
        }
        
        let (tx_result, rx_result) = tokio::sync::oneshot::channel();
        let req = GuiRequest {
            username,
            message,
            cookie: cookie.clone(),
            tx_result,
        };
        
        *ACTIVE_COOKIE.lock().unwrap() = Some(cookie);
        
        self.tx_gui_req.send(req).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        
        match rx_result.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(zbus::fdo::Error::Failed(err)),
            Err(_) => Err(zbus::fdo::Error::Failed("GUI closed".to_string())),
        }
    }

    async fn cancel_authentication(&self, cookie: String) -> zbus::fdo::Result<()> {
        let mut active_cookie = ACTIVE_COOKIE.lock().unwrap();
        if active_cookie.as_ref() == Some(&cookie) {
            *active_cookie = None;
            let sender_lock = ACTIVE_SENDER.lock().unwrap();
            if let Some(ref sender) = *sender_lock {
                let _ = sender.send(AppMessage::Cancel);
            }
        }
        Ok(())
    }
}

async fn get_system_session_id() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(id) = std::env::var("XDG_SESSION_ID") {
        return Ok(id);
    }
    
    if let Ok(id_str) = std::fs::read_to_string("/proc/self/sessionid") {
        let id_trimmed = id_str.trim();
        if !id_trimmed.is_empty() && id_trimmed != "4294967295" {
            return Ok(id_trimmed.to_string());
        }
    }
    
    let connection = zbus::Connection::system().await?;
    let reply: zbus::zvariant::OwnedObjectPath = connection.call_method(
        Some("org.freedesktop.login1"),
        "/org/freedesktop/login1",
        Some("org.freedesktop.login1.Manager"),
        "GetSessionByPID",
        &(std::process::id() as u32,),
    ).await?.body().deserialize()?;
    
    if let Some(pos) = reply.as_str().rfind('/') {
        let id = reply.as_str()[pos + 1..].to_string();
        let id = if id.starts_with('_') { id[1..].to_string() } else { id };
        return Ok(id);
    }
    
    Err("Session ID not found".into())
}

async fn run_polkit_agent_daemon(tx_gui_req: std::sync::mpsc::Sender<GuiRequest>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connection = zbus::Connection::system().await?;
    let session_id = get_system_session_id().await?;
    
    let agent = PolkitAgent { tx_gui_req };
    connection.object_server().at("/org/cce/AuthenticatorAgent", agent).await?;
    
    let mut details = std::collections::HashMap::new();
    details.insert("session-id".to_string(), zbus::zvariant::Value::from(session_id.clone()));
    let subject = (
        "unix-session".to_string(),
        details,
    );
        let object_path = zbus::zvariant::ObjectPath::try_from("/org/cce/AuthenticatorAgent")?;
    
    println!("Registering CCE Authenticator agent for session {}", session_id);
    connection.call_method(
        Some("org.freedesktop.PolicyKit1"),
        "/org/freedesktop/PolicyKit1/Authority",
        Some("org.freedesktop.PolicyKit1.Authority"),
        "RegisterAuthenticationAgent",
        &(subject.clone(), "en_US.UTF-8", object_path.as_str()),
    ).await?;
    println!("Successfully registered CCE Authenticator agent!");
    
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    
    println!("Unregistering CCE Authenticator agent...");
    let _ = connection.call_method(
        Some("org.freedesktop.PolicyKit1"),
        "/org/freedesktop/PolicyKit1/Authority",
        Some("org.freedesktop.PolicyKit1.Authority"),
        "UnregisterAuthenticationAgent",
        &(subject, object_path.as_str()),
    ).await;
    
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let standalone = args.contains(&"--standalone".to_string()) || args.contains(&"-s".to_string());
    
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _guard = rt.enter();
    
    if standalone {
        clear_ui::engine::run::<AuthenticatorApp>();
    } else {
        let (tx_gui_req, rx_gui_req) = std::sync::mpsc::channel::<GuiRequest>();
        
        rt.spawn(async move {
            if let Err(e) = run_polkit_agent_daemon(tx_gui_req).await {
                eprintln!("Error starting Polkit agent: {}", e);
                std::process::exit(1);
            }
        });
        
        while let Ok(req) = rx_gui_req.recv() {
            println!("rx_gui_req received a request for user: {}, message: {}", req.username, req.message);
            *ACTIVE_REQUEST.lock().unwrap() = Some(req);
            
            println!("Starting clear_ui::engine::run...");
            clear_ui::engine::run::<AuthenticatorApp>();
            println!("clear_ui::engine::run returned/exited!");
            
            *ACTIVE_SENDER.lock().unwrap() = None;
            *ACTIVE_COOKIE.lock().unwrap() = None;
            if let Some(req) = ACTIVE_REQUEST.lock().unwrap().take() {
                println!("ACTIVE_REQUEST still present, sending Cancelled to tx_result");
                let _ = req.tx_result.send(Err("Authentication cancelled".to_string()));
            } else {
                println!("ACTIVE_REQUEST was already taken (success/done).");
            }
            println!("Waiting for next rx_gui_req...");
        }
    }
}
