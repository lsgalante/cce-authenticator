use wayland_client::QueueHandle;
use cce_ui::engine::{Application, EngineState, LogicalPosition, LogicalSize, WindowSettings};
use cce_ui::widget::{
    Button, WidgetHost, ElementState, MouseButton, Key, NamedKey, KeyEvent, TextBox,
    MouseScrollDelta
};
use futures::StreamExt;
use std::sync::{Arc, Mutex};
use std::io::Write;
use tokio::sync::oneshot;
use std::ops::Deref;

const ACCENT: [f32; 4] = [0.30, 0.50, 0.32, 1.0];
const TOGGLE_OFF: [f32; 4] = [0.16, 0.16, 0.24, 1.0];
/// `TOGGLE_OFF` for a control that is not a control — see `fingerprint_interactive`.
const TOGGLE_INERT: [f32; 4] = [0.11, 0.11, 0.15, 1.0];


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

/// Cancellation state for every cookie polkitd has handed us, not just the one
/// whose window is up. Requests queue (the GUI runs on the main thread, one at a
/// time), so a CancelAuthentication can arrive for a cookie whose window has not
/// opened yet — or has not finished starting. A single active-cookie slot dropped
/// both of those on the floor and stranded the dialog.
struct CookieState {
    active: Option<String>,
    cancelled: Vec<String>,
}

static COOKIES: Mutex<CookieState> = Mutex::new(CookieState {
    active: None,
    cancelled: Vec::new(),
});

/// Whether the simulated authenticator may stand in for PAM.
///
/// Simulation reports success on its own, and in polkit mode that success is handed to
/// polkitd as `Ok(())` — granting the privileged action with nothing checked. So a live
/// request vetoes it outright, whatever asked for it: `CCE_AUTH_SIMULATE` once won here,
/// which turned every pkexec in the desktop into a silent auto-yes.
///
/// Gate on the dangerous state, never on an allowlist of the ways in. Kept as a pure
/// function of its inputs so the veto is settled by the test suite rather than by
/// arranging a live authentication bypass to check it.
fn simulate_allowed(polkit_mode: bool, env_requested: bool, uid: u32) -> bool {
    !polkit_mode && (env_requested || uid == 0)
}

/// Shorten a caption to what a column `width` logical px wide can show, breaking at
/// a word boundary.
///
/// The fingerprint column's captions are arbitrary-length strings from PAM, fprintd
/// and D-Bus errors (`No reader: <zbus error>`). The paint API clips to a rect, and a
/// clip rect is not a layout strategy — it cuts mid-word and gives no hint that
/// anything is missing. There is no cheap shaping call here to measure exactly, so the
/// budget comes from the advance observed at this size (~4.15 px/char at 9pt) and is
/// deliberately a few characters short: erring low only moves the ellipsis earlier.
///
/// The width is a parameter because the column is sized from the window — it was a
/// hardcoded 220px back when the dialog drew a fixed-size card inside itself.
fn fit_column(text: &str, width: f32) -> String {
    const PX_PER_CHAR: f32 = 4.15;
    let max_chars = ((width / PX_PER_CHAR) as usize).max(8);
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let head: String = text.chars().take(max_chars - 1).collect();
    let cut = head.rfind(' ').unwrap_or(head.len());
    format!("{}…", head[..cut].trim_end())
}

/// A toolkit color as the `[u8; 3]` the text prims take.
fn text_rgb(c: [f32; 4]) -> [u8; 3] {
    [
        (c[0] * 255.0).round().clamp(0.0, 255.0) as u8,
        (c[1] * 255.0).round().clamp(0.0, 255.0) as u8,
        (c[2] * 255.0).round().clamp(0.0, 255.0) as u8,
    ]
}

/// PAM service backing the standalone password check. Polkit mode never reaches it:
/// `polkit-agent-helper-1` runs its own `polkit-1` service inside the helper process.
const PAM_SERVICE: &str = "system-local-login";

/// Who we authenticate as when nothing more specific is known.
///
/// The passwd database is asked first and `$USER` is only a fallback, which is the
/// opposite of what this used to do: a user unit's environment is whatever
/// `systemctl --user import-environment` was told to carry, so `$USER` can simply be
/// absent here — and the old code answered that by authenticating as a login name
/// hardcoded to this developer's machine.
fn current_username() -> Option<String> {
    users::get_current_username()
        .map(|name| name.to_string_lossy().into_owned())
        .or_else(|| std::env::var("USER").ok())
        .filter(|name| !name.is_empty())
}

/// Consume a pending cancellation for `cookie`, reporting whether one was there.
fn take_cancelled(cookie: &str) -> bool {
    let mut st = COOKIES.lock().unwrap();
    match st.cancelled.iter().position(|c| c == cookie) {
        Some(pos) => {
            st.cancelled.remove(pos);
            true
        }
        None => false,
    }
}

struct AuthenticatorApp {
    password_box: cce_ui::widget::Adapted<TextBox>,
    verify_btn: cce_ui::widget::Adapted<cce_ui::widget::Button>,
    cancel_btn: cce_ui::widget::Adapted<cce_ui::widget::Button>,
    fingerprint_btn: cce_ui::widget::Adapted<cce_ui::widget::Button>,
    
    status_msg: String,
    status_is_error: bool,
    status_is_success: bool,
    
    fingerprint_msg: String,
    fingerprint_active: bool,
    fingerprint_success: bool,
    /// Whether the fingerprint button does anything if pressed. In polkit mode it
    /// does not: `pam_fprintd` inside the helper owns the reader, and whether it is
    /// even in the stack is PAM's business, not ours — so the column stays dimmed
    /// and unclaimed until a PAM message shows it is asking for a finger.
    fingerprint_interactive: bool,
    
    rx_auth: std::sync::mpsc::Receiver<AuthResult>,
    tx_auth: std::sync::mpsc::Sender<AuthResult>,
    
    width: f32,
    height: f32,
    
    simulate_mode: bool,
    glow_timer: f32,
    
    polkit_mode: bool,
    helper_stdin: Option<std::process::ChildStdin>,
    shared_child: Option<Arc<Mutex<Option<std::process::Child>>>>,
    /// Identity and cookie of the in-flight polkit request, kept so a failed
    /// attempt can start a fresh helper — see `RETRIES`.
    username: String,
    cookie: String,
    retries_left: u32,
    sender: calloop::channel::Sender<AppMessage>,
    ui_context: cce_ui::context::UiContext,
}

/// Extra helper runs allowed after the first attempt fails. `polkit-agent-helper-1`
/// runs one PAM conversation and exits, so a retry means a new process; bounding the
/// count also keeps a helper that fails *instantly* (a cookie polkitd no longer
/// recognises) from spawning in a tight loop.
const RETRIES: u32 = 2;

/// Start `polkit-agent-helper-1` for one attempt, returning its stdin and a handle
/// the Cancel path can kill. The reader thread translates the helper's PAM protocol
/// into AppMessages and reports the exit status as the attempt's verdict.
fn spawn_helper(
    username: &str,
    cookie: &str,
    sender: &calloop::channel::Sender<AppMessage>,
) -> std::io::Result<(std::process::ChildStdin, Arc<Mutex<Option<std::process::Child>>>)> {
    let mut child = std::process::Command::new("/usr/lib/polkit-1/polkit-agent-helper-1")
        .arg(username)
        .arg(cookie)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;

    let missing = |what| std::io::Error::new(std::io::ErrorKind::Other, what);
    let stdin = child.stdin.take().ok_or_else(|| missing("helper stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| missing("helper stdout"))?;

    let child_arc = Arc::new(Mutex::new(Some(child)));
    let reader_arc = child_arc.clone();
    let sender = sender.clone();

    std::thread::spawn(move || {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if let Some(prompt) = line.strip_prefix("PAM_PROMPT_ECHO_OFF ") {
                let _ = sender.send(AppMessage::PromptReceived(prompt.to_string(), false));
            } else if let Some(prompt) = line.strip_prefix("PAM_PROMPT_ECHO_ON ") {
                let _ = sender.send(AppMessage::PromptReceived(prompt.to_string(), true));
            } else if let Some(msg) = line.strip_prefix("PAM_ERROR_MSG ") {
                let _ = sender.send(AppMessage::StatusReceived(msg.to_string(), true));
            } else if let Some(msg) = line.strip_prefix("PAM_TEXT_INFO ") {
                let _ = sender.send(AppMessage::StatusReceived(msg.to_string(), false));
            }
        }

        // Cancel takes the child to kill it; finding None here means this attempt
        // was abandoned deliberately and owes no verdict.
        let mut lock = reader_arc.lock().unwrap();
        if let Some(mut child) = lock.take() {
            drop(lock);
            match child.wait() {
                Ok(status) if status.success() => {
                    let _ = sender.send(AppMessage::AuthDone(AuthResult::Success));
                }
                _ => {
                    let _ = sender.send(AppMessage::AuthDone(AuthResult::Failure(
                        "Authentication failed".to_string(),
                    )));
                }
            }
        }
    });

    Ok((stdin, child_arc))
}

impl Application for AuthenticatorApp {
    type Message = AppMessage;

    fn ui_context(&self) -> Option<&cce_ui::context::UiContext> {
        Some(&self.ui_context)
    }

    fn new(_qh: &QueueHandle<EngineState<Self>>, sender: calloop::channel::Sender<Self::Message>) -> Self {
        let password_box = TextBox::new(String::new())
            .with_password(true)
            .with_label("PASSWORD");
            
        let verify_btn = Button::new(0.0, 0.0, 100.0, 32.0).with_label("Verify");
        let cancel_btn = Button::new(0.0, 0.0, 100.0, 32.0).with_label("Cancel");
        let mut fingerprint_btn = Button::new(0.0, 0.0, 120.0, 120.0).with_label("Scan");
        
        let (tx_auth, rx_auth) = std::sync::mpsc::channel();
        
        let active_req = ACTIVE_REQUEST.lock().unwrap();
        let polkit_mode = active_req.is_some();
        
        let mut helper_stdin = None;
        let mut shared_child = None;
        let mut status_msg = "Authenticate using password or fingerprint".to_string();
        // Simulation stands in for PAM, and a simulated success answers polkitd with
        // Ok(()) — i.e. grants the privileged action having checked no credential at
        // all. So it is gated on the unsafe state (a real request is in flight), not
        // on how simulation was asked for: with a request present it is off, full
        // stop, whatever CCE_AUTH_SIMULATE says. The password and fingerprint paths
        // below exclude it a second time on the same condition.
        let simulate_mode = simulate_allowed(
            polkit_mode,
            std::env::var("CCE_AUTH_SIMULATE").is_ok(),
            users::get_current_uid(),
        );

        let mut username = String::new();
        let mut cookie = String::new();

        // In polkit mode the button reports the reader rather than driving it, so it
        // should not read as something to press.
        if polkit_mode {
            fingerprint_btn.set_label("Reader");
        }

        if let Some(ref req) = *active_req {
            if std::env::var("CCE_AUTH_SIMULATE").is_ok() {
                log::warn!(
                    "CCE_AUTH_SIMULATE is set and is being IGNORED: a real polkit request is in flight"
                );
            }
            status_msg = req.message.clone();
            username = req.username.clone();
            cookie = req.cookie.clone();

            match spawn_helper(&username, &cookie, &sender) {
                Ok((stdin, child)) => {
                    helper_stdin = Some(stdin);
                    shared_child = Some(child);
                }
                Err(e) => {
                    status_msg = format!("Failed to spawn helper: {}", e);
                }
            }
        }

        // Store active sender for Cancel D-Bus calls
        *ACTIVE_SENDER.lock().unwrap() = Some(sender.clone());

        // A cancel that landed while this window was starting found no sender to
        // deliver to; claim it now that there is one.
        if polkit_mode && take_cancelled(&cookie) {
            log::info!("cookie {} was cancelled while its window was starting", cookie);
            let _ = sender.send(AppMessage::Cancel);
        }

        let mut app = Self {
            password_box,
            verify_btn,
            cancel_btn,
            fingerprint_btn,
            
            status_msg,
            status_is_error: false,
            status_is_success: false,
            
            fingerprint_msg: if polkit_mode {
                "Handled by PAM — follow the prompt".to_string()
            } else {
                "Fingerprint scanner ready".to_string()
            },
            fingerprint_active: false,
            fingerprint_success: false,
            fingerprint_interactive: !polkit_mode,
            
            rx_auth,
            tx_auth,
            
            width: 800.0,
            height: 600.0,
            
            simulate_mode,
            glow_timer: 0.0,
            
            polkit_mode,
            helper_stdin,
            shared_child,
            username,
            cookie,
            retries_left: RETRIES,
            sender: sender.clone(),
            ui_context: cce_ui::context::UiContext::new(),
        };
        
        let tx = app.tx_auth.clone();
        if app.simulate_mode {
            app.status_msg = "SIMULATION MODE: use password 'password' or click fingerprint".to_string();
            app.fingerprint_msg = "Click fingerprint sensor to scan".to_string();
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                log::info!("Auto-authenticating in simulation mode...");
                let _ = tx_clone.send(AuthResult::Success);
            });
        } else if !app.polkit_mode {
            let Some(username) = current_username() else {
                app.fingerprint_msg = "Cannot determine the current user".to_string();
                return app;
            };
            tokio::spawn(async move {
                if let Err(e) = run_dbus_fingerprint(username, tx.clone()).await {
                    let _ = tx.send(AuthResult::FingerprintStatus(format!("No reader: {}", e)));
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    let _ = tx.send(AuthResult::FingerprintStatus("Simulation mode active. Click icon to verify.".to_string()));
                }
            });
        } else {
            // In Polkit mode, pam_fprintd.so running inside polkit-agent-helper-1
            // will handle claiming and verifying the fingerprint reader natively.
        }
        
        app
    }

    fn settings(&self) -> WindowSettings {
        WindowSettings {
            title: "CCE Authenticator".to_string(),
            app_id: "cce-authenticator".to_string(),
            width: 640,
            // Sized to the content now that there is no inset card: title band,
            // two column wells, status shelf. At 400 the wells ran ~70px past
            // anything in them and the dialog read as half empty.
            height: 360,
            fullscreen: false,
            min_size: Some((560, 340)),
        }
    }

    /// A session modal is a utility window: two fixed columns and a status
    /// shelf, nothing worth resizing, and nothing it should ever inherit.
    ///
    /// The size matters more here than for an ordinary tool. The compositor
    /// restores a saved size per app_id over the client's request, so before
    /// this the prompt came back at whatever it was last left at — and a
    /// prompt is not something the user chose to open at a size, it is
    /// something that appeared. Utility means no geometry is saved for it, so
    /// none can be restored: every prompt is the shape this dialog asks for.
    /// It also drops the resize affordance (the whole border band moves it)
    /// and keeps the window out of the overview displacement.
    ///
    /// Placement stays the compositor's — `Window::try_center_on_view` centers
    /// this app_id on the current view, and it is exempt from Utility's
    /// self-sizing for position only.
    fn utility(&self) -> bool {
        true
    }

    fn update(&mut self, msg: Self::Message, needs_rebuild: &mut bool, exit: &mut bool) {
        *needs_rebuild = true;
        match msg {
            AppMessage::PasswordVerify => {
                if self.status_is_success { return; }
                let password = self.password_box.text.clone();
                self.status_msg = "Verifying password...".to_string();
                self.status_is_error = false;
                
                // Polkit mode answers through the helper or not at all — never through
                // the local PAM/simulation branch, which can report success on its own.
                if self.polkit_mode {
                    match self.helper_stdin {
                        Some(ref mut stdin) => {
                            let _ = writeln!(stdin, "{}", password);
                            let _ = stdin.flush();
                            self.password_box.text.clear();
                        }
                        None => {
                            self.status_msg =
                                "No authentication helper — press Escape to cancel".to_string();
                            self.status_is_error = true;
                        }
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
                            let Some(username) = current_username() else {
                                let _ = tx.send(AuthResult::Failure(
                                    "Cannot determine the current user".to_string(),
                                ));
                                return;
                            };
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
                if self.polkit_mode {
                    // PAM fprintd handles the hardware reader natively in Polkit mode
                    return;
                }
                self.fingerprint_active = true;
                self.fingerprint_msg = "Place finger on reader...".to_string();
                
                let tx = self.tx_auth.clone();
                let simulate = self.simulate_mode;
                
                tokio::spawn(async move {
                    if simulate {
                        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                        let _ = tx.send(AuthResult::Success);
                    } else {
                        let Some(username) = current_username() else {
                            let _ = tx.send(AuthResult::FingerprintStatus(
                                "Cannot determine the current user".to_string(),
                            ));
                            return;
                        };
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
                        // `kill` only signals — Rust never reaps on drop — and taking the
                        // child here means the reader thread won't wait() on it either, so
                        // without this every cancelled prompt left a zombie for the life of
                        // the session. Reaped off-thread because this daemon must never
                        // wedge on a wait: it is the session's only polkit agent.
                        std::thread::spawn(move || {
                            let _ = child.wait();
                        });
                    }
                }
                *exit = true;
            }
            AppMessage::PromptReceived(prompt, _echo) => {
                self.password_box.set_label(&prompt);
                self.password_box.text.clear();
            }
            AppMessage::StatusReceived(msg, is_error) => {
                self.status_msg = msg.clone();
                self.status_is_error = is_error;
                self.status_is_success = false;
                if msg.to_lowercase().contains("finger") {
                    // PAM's wording is a whole sentence naming the finger and the
                    // reader, and the wide status line above already carries it
                    // verbatim. Repeating it inside the narrow column printed it
                    // twice and cut the copy mid-word ("…on the fingerprint read"),
                    // so the column reports the state instead.
                    self.fingerprint_active = true;
                    self.fingerprint_msg = "Waiting for finger…".to_string();
                }
            }
            AppMessage::AuthDone(res) => {
                log::debug!("AppMessage::AuthDone received: {:?}", res);
                match res {
                    AuthResult::Success => {
                        self.status_is_success = true;
                        self.status_is_error = false;
                        self.fingerprint_success = true;
                        self.fingerprint_active = false;
                        self.status_msg = "Authentication Successful!".to_string();
                        self.fingerprint_msg = "Authenticated".to_string();
                        
                        if self.polkit_mode {
                            log::info!("AuthResult::Success in Polkit mode. Sending Ok to tx_result and spawning exit timer.");
                            if let Some(req) = ACTIVE_REQUEST.lock().unwrap().take() {
                                let _ = req.tx_result.send(Ok(()));
                            } else {
                                log::warn!("WARNING: ACTIVE_REQUEST was None inside AuthDone(Success)!");
                            }
                            let tx = self.tx_auth.clone();
                            tokio::spawn(async move {
                                log::debug!("Exit timer task spawned, sleeping 800ms...");
                                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                                log::debug!("Exit timer slept 800ms. Sending ExitWindow to tx.");
                                let _ = tx.send(AuthResult::ExitWindow);
                            });
                        } else {
                            log::info!("AuthResult::Success in standalone mode. Exiting process in 1000ms.");
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                                std::process::exit(0);
                            });
                        }
                    }
                    AuthResult::ExitWindow => {
                        log::info!("AuthResult::ExitWindow received in update. Setting exit = true.");
                        *exit = true;
                    }
                    AuthResult::Failure(err) => {
                        log::error!("AuthResult::Failure received: {}", err);
                        self.status_is_error = true;
                        self.status_msg = err;

                        // The helper has exited — it runs one PAM conversation per
                        // process — so the stdin we still hold is a closed pipe and
                        // Verify would write into nothing. A retry needs a fresh one.
                        if self.polkit_mode {
                            self.helper_stdin = None;
                            self.shared_child = None;
                            self.password_box.text.clear();

                            if self.retries_left == 0 {
                                log::warn!("no attempts left for cookie {}", self.cookie);
                                self.status_msg =
                                    format!("{} — press Escape to cancel", self.status_msg);
                            } else {
                                self.retries_left -= 1;
                                match spawn_helper(&self.username, &self.cookie, &self.sender) {
                                    Ok((stdin, child)) => {
                                        log::info!(
                                            "restarted helper for another attempt ({} left after this)",
                                            self.retries_left
                                        );
                                        self.helper_stdin = Some(stdin);
                                        self.shared_child = Some(child);
                                    }
                                    Err(e) => {
                                        log::error!("could not restart helper: {}", e);
                                        self.status_msg =
                                            format!("Could not restart helper: {}", e);
                                    }
                                }
                            }
                        }
                    }
                    AuthResult::FingerprintStatus(status) => {
                        log::info!("AuthResult::FingerprintStatus received: {}", status);
                        if !self.polkit_mode
                            && (status.contains("Simulation mode active")
                                || status.contains("No reader"))
                        {
                            self.simulate_mode = true;
                        }
                        self.fingerprint_msg = status;
                    }
                }
            }
        }
    }

    /// `tick` drains `rx_auth`, a std channel the runner cannot see; without
    /// this the password verdict would wait for the next unrelated event.
    fn idle_poll_interval(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_millis(50))
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

    fn display_list(&mut self, size: LogicalSize, scale: f64) -> Option<cce_ui::scene::paint::DisplayList> {
        // Id-rooted router: dispatch roots resolve through the registry — keep the
        // four roots' registrations fresh each frame (idempotent; the dialog assembles
        // its frame by hand, so nothing else registers them).
        {
            let (id, ptr) = (self.verify_btn.id(), self.verify_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.cancel_btn.id(), self.cancel_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.fingerprint_btn.id(), self.fingerprint_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.password_box.id(), self.password_box.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
        }
        // Phase 6ag single paint path: the whole frame — card, columns, widgets, and all
        // text — is this one list. NOTE this migration is a FIX, not a match: the app's old
        // FontSystem shaped buffers whose fontdb face IDs did not resolve in the engine's
        // render FontSystem, so ALL of this dialog's text was silently invisible (the 6e
        // class). Shaped as display-list Text prims through the engine cache, it renders.
        use cce_ui::scene::layout::Rect;
        cce_ui::scale::set_scale_factor(scale as f32);
        let sw = size.width as f32;
        let sh = size.height as f32;
        self.width = sw;
        self.height = sh;

        let mut pc = cce_ui::scene::paint::PaintCtx::new();

        // ── The window plate ──
        //
        // The window IS the dialog: the standard root plate (cce-ui
        // `PlateSpec::window`), one lit slab whose rolled perimeter reads as
        // the physical edge the silhouette already implies. It replaced a
        // dimmed surface with a 540x320 "card" outlined in four square quads.
        pc.root_plate(sw, sh);

        // ── Layout ──
        //
        // Spacing comes off the toolkit's ladder, never a literal: the window
        // inset for anything against the window edge, the root gap between the
        // dialog's parts (the two columns, the wells and the status band), the
        // pane rung inside each well.
        let pad = cce_ui::layout::root_plate_inset();
        let status_h = 40.0f32;
        let gutter = cce_ui::layout::root_plate_gap();
        let caption_h = 22.0f32;
        // TODO(style): the title row — a 15pt line plus its run down to the
        // captions folded into one number; not a rung, so it stays a height.
        let title_h = 34.0f32;

        let status_y = sh - status_h;
        let content_y = pad + title_h;
        let col_w = ((sw - pad * 2.0 - gutter) / 2.0).max(140.0);
        let fp_col_x = pad;
        let pw_col_x = pad + col_w + gutter;
        let well_y = content_y + caption_h;
        let well_h = (status_y - gutter - well_y).max(90.0);
        let well_r = cce_ui::layout::plate_corner_radius();
        let well_depth = cce_ui::layout::bevel_width().min(well_h * 0.2);

        // Both columns are wells carved into the plate — the captions label a real
        // recess instead of floating over an undifferentiated fill.
        for x in [fp_col_x, pw_col_x] {
            pc.recess(
                Rect { x, y: well_y, width: col_w, height: well_h },
                (well_r, well_r, well_r, well_r),
                well_depth,
            );
        }

        // The status line gets the statusbar treatment: a band carved across the foot
        // of the plate, top wall only so the seam reads as a shelf rather than a box
        // inset from edges the window already rounds.
        pc.recess_edges(
            Rect { x: 0.0, y: status_y, width: sw, height: status_h },
            (0.0, 0.0, 0.0, 0.0),
            cce_ui::layout::bar_wall_width(),
            (true, false, false, false),
        );

        // ── Widget geometry ──
        //
        // The two columns fill their wells differently because their contents differ:
        // the reader is one target, so it centers; the password column is a form, so
        // it runs input at the top and actions at the foot.
        // Each well is the dialog's pane: its rim-to-content inset and the gap
        // between the things inside it are the pane rung.
        let inset = cce_ui::layout::plate_padding();
        let gap = cce_ui::layout::plate_gap();
        let cap_h = 34.0f32; // two lines at 9pt, the longest PAM/fprintd captions
        // TODO(style): 78 is the vertical room the caption block reserves under
        // the reader (gap + cap_h + slack), pinned as one number when the reader
        // was sized; a size, not a rung.
        let fp_btn_w = 150.0f32.min(col_w - inset * 2.0).min(well_h - 78.0).max(64.0);
        let fp_btn_h = fp_btn_w;
        let fp_btn_x = fp_col_x + (col_w - fp_btn_w) / 2.0;
        // Target + caption ride as one block centered in the well. Top-anchored, the
        // block left a third of the column empty under it and the column read as
        // unfinished rather than as a target with room around it.
        let fp_block_h = fp_btn_h + gap + cap_h;
        let fp_btn_y = well_y + ((well_h - fp_block_h) / 2.0).max(inset);
        self.fingerprint_btn.set_rect(fp_btn_x, fp_btn_y, fp_btn_w, fp_btn_h);

        // The reader's state color rides on the widget so the plate path paints it.
        // It used to be a quad drawn UNDER the widget loop's `quad(w.rect(), w.color())`
        // on the identical rect — so every state (the success accent, the scanning
        // glow, the dimmed-inert fill) was overpainted by the button's flat default
        // and none of them ever reached the screen.
        self.fingerprint_btn.bg = Some(if self.fingerprint_success {
            ACCENT
        } else if self.fingerprint_active {
            let alpha = 0.4 + 0.3 * self.glow_timer.sin();
            [0.16, 0.41, 0.18, alpha]
        } else if self.fingerprint_interactive {
            TOGGLE_OFF
        } else {
            // PAM owns the reader here, and the click handler drops presses on the
            // floor — so don't paint this like something that responds to one.
            TOGGLE_INERT
        });

        let pw_inner_x = pw_col_x + inset;
        let pw_inner_w = col_w - inset * 2.0;
        // TODO(style): 40 places the entry below the well's top lip — more than
        // the pane inset, less than a control gap; a placement, not a rung.
        self.password_box.set_rect(pw_inner_x, well_y + 40.0, pw_inner_w, 36.0);

        // The two actions split the column. They were a fixed 100px, which "Verify
        // Password" overran on both sides at the DE's 14pt control font — the label
        // is "Verify" now, and the width follows the column instead of a constant.
        let btn_w = ((pw_inner_w - gap) / 2.0).max(72.0);
        let btn_h = 32.0f32;
        let btn_y = well_y + well_h - inset - btn_h;
        self.verify_btn.set_rect(pw_inner_x, btn_y, btn_w, btn_h);
        self.cancel_btn.set_rect(pw_inner_x + pw_inner_w - btn_w, btn_y, btn_w, btn_h);

        // Run each control through the real paint walk, which is how every other cce
        // app draws its widgets: the widget's own `Paint` impl, so a Button emits the
        // sunken `inset_plate` its `raised` style means and a TextBox its recessed
        // well, along with hover/press/focus state and its text.
        //
        // NOT `append_widget_plate` — that is the designer's escape hatch, and it
        // resolves a plate through `plate_bevel()`/`solid_border()`, neither of which
        // `Adapted` forwards from `Button`. Every control came out as a bevel filled
        // with the configured button face, which this DE sets to #00000000: invisible.
        for w in self.widgets_iter() {
            cce_ui::scene::painter::paint_root_into(&self.ui_context, w, &mut pc);
        }

        if self.fingerprint_active {
            // style: deliberate — the scan line's 10px stand-off inside the
            // reader target is the glyph's own geometry, not a layout gap.
            let scan_y = fp_btn_y + 10.0
                + (50.0 + 50.0 * self.glow_timer.sin()).clamp(0.0, fp_btn_h - 20.0);
            pc.quad(
                Rect { x: fp_btn_x + 10.0, y: scan_y, width: fp_btn_w - 20.0, height: 2.0 },
                [0.30, 0.90, 0.32, 0.8],
            );
        }

        // ── Text ──
        let caption = cce_ui::color::control_label_color_detached_u8();
        pc.text_with(
            "CCE AUTHENTICATOR".to_string(),
            pad,
            pad,
            15.0,
            text_rgb(cce_ui::color::TEXT_HEADER),
            None,
            None,
        );
        pc.text_with("FINGERPRINT AUTHENTICATION".to_string(), fp_col_x, content_y, 10.0, caption, None, None);
        pc.text_with("PASSWORD AUTHENTICATION".to_string(), pw_col_x, content_y, 10.0, caption, None, None);

        let fp_msg_color = if self.fingerprint_success {
            [0xa0, 0xee, 0xa0]
        } else if self.fingerprint_interactive || self.fingerprint_active {
            text_rgb(cce_ui::color::TEXT_FG)
        } else {
            caption
        };
        let fp_msg_x = fp_col_x + inset;
        let fp_msg_w = col_w - inset * 2.0;
        let fp_msg_y = fp_btn_y + fp_btn_h + gap;
        pc.text_with(
            fit_column(&self.fingerprint_msg, fp_msg_w),
            fp_msg_x,
            fp_msg_y,
            9.0,
            fp_msg_color,
            None,
            Some([fp_msg_x, fp_msg_y, fp_msg_x + fp_msg_w, fp_msg_y + cap_h]),
        );

        let status_color = if self.status_is_success {
            [0xa0, 0xee, 0xa0]
        } else if self.status_is_error {
            [0xee, 0x5c, 0x5c]
        } else {
            text_rgb(cce_ui::color::TEXT_FG)
        };
        let status_text_y = status_y + (status_h - 12.0) / 2.0;
        pc.text_with(
            self.status_msg.clone(),
            pad,
            status_text_y,
            10.0,
            status_color,
            None,
            Some([pad, status_y, sw - pad, sh]),
        );

        Some(pc.finish())
    }

    fn display_list_text(&self) -> bool {
        true
    }

    fn handle_pointer_move(&mut self, pos: LogicalPosition, needs_rebuild: &mut bool) {
        // Routed dispatch (6bd shrink): one Event per widget root through the router.
        let mv = cce_ui::widget::Event::PointerMove { x: pos.x, y: pos.y, local_x: pos.x, local_y: pos.y };
        let ctx = &mut self.ui_context;
        // `bg` is deliberately absent: `ContentBg::hit` is unconditionally false, so it
        // can never consume a pointer event, and it is the one root this dialog paints
        // without registering — routing to it logged "unregistered/stale root … event
        // dropped" on every motion event for the life of the daemon.
        if ctx.propagate_event(&mv, self.password_box.id()) { *needs_rebuild = true; }
        if ctx.propagate_event(&mv, self.verify_btn.id()) { *needs_rebuild = true; }
        if ctx.propagate_event(&mv, self.cancel_btn.id()) { *needs_rebuild = true; }
        if ctx.propagate_event(&mv, self.fingerprint_btn.id()) { *needs_rebuild = true; }
    }

    fn handle_mouse_input(&mut self, button: MouseButton, state: ElementState, pos: LogicalPosition, needs_rebuild: &mut bool) -> Option<Self::Message> {
        let (lx, ly) = (pos.x, pos.y);
        let ev = cce_ui::widget::Event::MouseButton { button, state, x: lx, y: ly, local_x: lx, local_y: ly };

        if { let root = self.verify_btn.id(); self.ui_context.propagate_event(&ev, root) } {
            *needs_rebuild = true;
        }
        if self.verify_btn.take_click() {
            return Some(AppMessage::PasswordVerify);
        }
        
        if { let root = self.cancel_btn.id(); self.ui_context.propagate_event(&ev, root) } {
            *needs_rebuild = true;
        }
        if self.cancel_btn.take_click() {
            return Some(AppMessage::Cancel);
        }
        
        if { let root = self.fingerprint_btn.id(); self.ui_context.propagate_event(&ev, root) } {
            *needs_rebuild = true;
        }
        if self.fingerprint_btn.take_click() {
            return Some(AppMessage::FingerprintScanStart);
        }
        
        let tb = &mut self.password_box;
        if state == ElementState::Pressed && !tb.hit_test(lx, ly, &self.ui_context) {
            tb.unfocus();
        }
        if { let root = tb.id(); self.ui_context.propagate_event(&ev, root) } {
            *needs_rebuild = true;
        }
        
        None
    }

    fn handle_mouse_wheel(&mut self, _delta: &MouseScrollDelta, _pos: LogicalPosition, _needs_rebuild: &mut bool) {}

    fn handle_key_input(&mut self, event: &KeyEvent, needs_rebuild: &mut bool) -> Option<Self::Message> {
        if event.state == ElementState::Pressed && !event.repeat {
            if let Key::Named(NamedKey::Tab) = event.logical_key {
                if self.password_box.focused(&self.ui_context) {
                    self.password_box.unfocus();
                    self.verify_btn.focus();
                } else if self.verify_btn.focused(&self.ui_context) {
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
                if self.password_box.focused(&self.ui_context) {
                    return Some(AppMessage::PasswordVerify);
                }
            }
        }
        
        let kev = cce_ui::widget::Event::KeyInput(event.clone());
        let root = self.password_box.id();
        if self.ui_context.propagate_event(&kev, root) {
            *needs_rebuild = true;
        }
        
        None
    }
}

impl AuthenticatorApp {
    /// The dialog's four real controls, in paint order.
    ///
    /// A full-window `ContentBg` used to lead this list. It was the flat backdrop the
    /// window plate now is, and once the widgets paint as plates it became actively
    /// destructive: `append_widget_plate` would have drawn its fill over the plate,
    /// erasing the lit edge and every carve under it.
    fn widgets_iter(&self) -> Vec<&dyn WidgetHost> {
        vec![
            &self.password_box,
            &self.verify_btn,
            &self.cancel_btn,
            &self.fingerprint_btn,
        ]
    }
}

fn run_pam_auth(username: &str, password: &str) -> Result<(), String> {
    unsafe {
        let service = PAM_SERVICE;
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
        "VerifyStart",
        &("any",),
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
        log::info!("begin_authentication called! message = {:?}, cookie = {:?}", message, cookie);
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
        // polkit names the identity it wants authenticated. If it named one we could
        // not resolve, fall back to our own — but refuse rather than guess a name,
        // because the wrong identity here means prompting for a password that cannot
        // authorize the action.
        if username.is_empty() {
            username = current_username().ok_or_else(|| {
                zbus::fdo::Error::Failed("no resolvable unix-user identity".to_string())
            })?;
            log::warn!("no unix-user identity in the request; falling back to {}", username);
        }


        let (tx_result, rx_result) = tokio::sync::oneshot::channel();
        let req = GuiRequest {
            username,
            message,
            cookie: cookie.clone(),
            tx_result,
        };
        
        self.tx_gui_req.send(req).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        
        match rx_result.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(zbus::fdo::Error::Failed(err)),
            Err(_) => Err(zbus::fdo::Error::Failed("GUI closed".to_string())),
        }
    }

    async fn cancel_authentication(&self, cookie: String) -> zbus::fdo::Result<()> {
        log::info!("cancel_authentication called for cookie {:?}", cookie);

        // Record the cancellation for *any* cookie we have been handed, then try to
        // deliver it. Whoever owns this cookie consumes the record: the main loop
        // before opening its window, or `new()` once it has a sender. Recording
        // unconditionally is what makes the queued and still-starting cases work.
        let is_active = {
            let mut st = COOKIES.lock().unwrap();
            if !st.cancelled.iter().any(|c| c == &cookie) {
                st.cancelled.push(cookie.clone());
            }
            st.active.as_deref() == Some(cookie.as_str())
        };

        if is_active {
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
    
    log::info!("Registering CCE Authenticator agent for session {}", session_id);
    connection.call_method(
        Some("org.freedesktop.PolicyKit1"),
        "/org/freedesktop/PolicyKit1/Authority",
        Some("org.freedesktop.PolicyKit1.Authority"),
        "RegisterAuthenticationAgent",
        &(subject.clone(), "en_US.UTF-8", object_path.as_str()),
    ).await?;
    log::info!("Successfully registered CCE Authenticator agent!");
    
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
    
    log::info!("Unregistering CCE Authenticator agent...");
    let _ = connection.call_method(
        Some("org.freedesktop.PolicyKit1"),
        "/org/freedesktop/PolicyKit1/Authority",
        Some("org.freedesktop.PolicyKit1.Authority"),
        "UnregisterAuthenticationAgent",
        &(subject, object_path.as_str()),
    ).await;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Record a cancellation the way the D-Bus handler does, reporting whether it
    /// would have been delivered to a live window.
    fn cancel(cookie: &str) -> bool {
        let mut st = COOKIES.lock().unwrap();
        if !st.cancelled.iter().any(|c| c == cookie) {
            st.cancelled.push(cookie.to_string());
        }
        st.active.as_deref() == Some(cookie)
    }

    fn claim(cookie: &str) {
        COOKIES.lock().unwrap().active = Some(cookie.to_string());
    }

    fn finish(cookie: &str) {
        let mut st = COOKIES.lock().unwrap();
        st.active = None;
        st.cancelled.retain(|c| c != cookie);
    }

    /// Exhaustive over the gate's inputs, because this is the one invariant whose
    /// failure grants root. Checking it live would mean standing up a working
    /// authentication bypass and confirming it doesn't fire — the test settles it
    /// without ever putting the machine in that state.
    #[test]
    fn a_live_request_vetoes_simulation() {
        for &env_requested in &[true, false] {
            for &uid in &[0u32, 1000] {
                assert!(
                    !simulate_allowed(true, env_requested, uid),
                    "polkit mode must veto simulation (env={env_requested}, uid={uid}): \
                     a simulated success answers polkitd with Ok(()) and grants the action"
                );
            }
        }

        // Outside polkit mode simulation must still work, or --standalone stops being
        // a usable test window and the veto above is untestable in practice.
        assert!(simulate_allowed(false, true, 1000), "CCE_AUTH_SIMULATE drives standalone");
        assert!(simulate_allowed(false, false, 0), "root standalone simulates without the var");
        assert!(!simulate_allowed(false, false, 1000), "no request, no var, not root: real PAM");
    }

    #[test]
    fn column_captions_never_cut_mid_word() {
        // Roughly the interior of a column in the default 640px-wide window.
        const W: f32 = 245.0;

        // The message that exposed this — clipping rendered "…on the fingerprint
        // read" — now fits whole: the column grew from a hardcoded 220px to its
        // share of the window. Asserted, because it is the reason the budget had
        // to stop being a constant.
        let pam = "Place your right middle finger on the fingerprint reader";
        assert_eq!(fit_column(pam, W), pam, "the column is wide enough for PAM's wording now");
        assert!(fit_column(pam, 220.0).ends_with('…'), "…but not at the old width");

        // The genuinely unbounded captions are the D-Bus errors.
        let err = "No reader: org.freedesktop.DBus.Error.ServiceUnknown: \
                   The name net.reactivated.Fprint was not provided by any .service files";
        let fitted = fit_column(err, W);
        assert!(fitted.ends_with('…'), "long captions must show they were cut");
        let kept = fitted.trim_end_matches('…');
        assert!(err.starts_with(kept), "the kept head must be a real prefix: {fitted}");
        // A word boundary means the character the cut dropped was a space — that is
        // the whole difference between this and the clip rect it replaced.
        assert_eq!(
            err[kept.len()..].chars().next(),
            Some(' '),
            "cut fell mid-word: {fitted}"
        );

        // Short enough to stand as-is, ellipsis included or not.
        assert_eq!(fit_column("Waiting for finger…", W), "Waiting for finger…");
        assert_eq!(fit_column("", W), "");

        // No spaces to break on, and multi-byte characters: must not panic or slice
        // through a char boundary.
        let unbroken = "x".repeat(200);
        assert!(fit_column(&unbroken, W).ends_with('…'));
        assert!(fit_column(&"é".repeat(200), W).ends_with('…'));

        // A window dragged to its minimum still has to produce something, not panic
        // on an underflowing budget — the width is a layout value now, not a constant.
        assert!(!fit_column(pam, 1.0).is_empty());
        assert!(!fit_column(pam, 0.0).is_empty());
    }

    /// The orderings that a single active-cookie slot got wrong. One test, run in
    /// sequence, because COOKIES is process-global.
    #[test]
    fn cancellation_survives_every_ordering() {
        // Cancel lands before the main loop claims the cookie: not deliverable, but
        // the record is waiting when the loop looks, so the window never opens.
        assert!(!cancel("early"));
        claim("early");
        assert!(take_cancelled("early"), "cancel before claim must be seen");
        finish("early");

        // Cancel lands after the claim but before the window has a sender. It reads
        // as deliverable, yet there is nothing to deliver to — new() consumes it.
        claim("starting");
        assert!(cancel("starting"), "cancel for the claimed cookie is active");
        assert!(take_cancelled("starting"), "new() must still find it");
        finish("starting");

        // Cancel for a queued cookie while another window is up. It must not be
        // mistaken for the active one, and must survive that window closing.
        claim("open");
        assert!(!cancel("queued"), "a queued cookie is not the active one");
        assert!(!take_cancelled("open"), "the open window was never cancelled");
        finish("open");
        claim("queued");
        assert!(
            take_cancelled("queued"),
            "a queued cancel must outlive the window ahead of it"
        );
        finish("queued");

        // Nothing left behind.
        let st = COOKIES.lock().unwrap();
        assert!(st.active.is_none());
        assert!(st.cancelled.is_empty(), "cancelled cookies leaked: {:?}", st.cancelled);
    }
}

fn main() {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    let standalone = args.contains(&"--standalone".to_string()) || args.contains(&"-s".to_string());
    
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _guard = rt.enter();
    
    if standalone {
        cce_ui::engine::run::<AuthenticatorApp>();
    } else {
        let (tx_gui_req, rx_gui_req) = std::sync::mpsc::channel::<GuiRequest>();
        
        rt.spawn(async move {
            if let Err(e) = run_polkit_agent_daemon(tx_gui_req).await {
                log::error!("Error starting Polkit agent: {}", e);
                std::process::exit(1);
            }
        });
        
        while let Ok(req) = rx_gui_req.recv() {
            log::info!("rx_gui_req received a request for user: {}, message: {}", req.username, req.message);
            let cookie = req.cookie.clone();

            // Claim the cookie before checking, so a cancel racing this point either
            // finds it active (and delivers, or is consumed by `new()`) or lands in
            // `cancelled` in time to be seen right here. Requests wait their turn in
            // the channel, and polkitd may well give up on one before its turn comes.
            COOKIES.lock().unwrap().active = Some(cookie.clone());
            if take_cancelled(&cookie) {
                log::info!("cookie {} was cancelled before its window opened", cookie);
                COOKIES.lock().unwrap().active = None;
                let _ = req.tx_result.send(Err("Authentication cancelled".to_string()));
                continue;
            }

            *ACTIVE_REQUEST.lock().unwrap() = Some(req);

            log::info!("Starting cce_ui::engine::run...");
            cce_ui::engine::run::<AuthenticatorApp>();
            log::info!("cce_ui::engine::run returned/exited!");

            *ACTIVE_SENDER.lock().unwrap() = None;
            {
                let mut st = COOKIES.lock().unwrap();
                st.active = None;
                st.cancelled.retain(|c| c != &cookie);
            }
            if let Some(req) = ACTIVE_REQUEST.lock().unwrap().take() {
                log::info!("ACTIVE_REQUEST still present, sending Cancelled to tx_result");
                let _ = req.tx_result.send(Err("Authentication cancelled".to_string()));
            } else {
                log::info!("ACTIVE_REQUEST was already taken (success/done).");
            }
            log::info!("Waiting for next rx_gui_req...");
        }
    }
}
