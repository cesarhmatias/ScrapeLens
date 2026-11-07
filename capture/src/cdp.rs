//! cdp module for the capture crate; moved from lib.rs by T29.

use super::*;

pub(crate) const CDP_TARGET_METHODS: &[&str] = &[
    "Target.attachedToTarget",
    "Target.detachedFromTarget",
    "Target.targetInfoChanged",
    "Target.attachFailed",
    "Capture.sessionSetup",
    "Capture.targetSetupTimeout",
    "Capture.targetSetupAborted",
    "Capture.targetSetupError",
    "Target.targetDestroyed",
];

/// Warning code imported by the core (`cdp.target_setup_timeout`).
pub(crate) const CDP_TARGET_SETUP_TIMEOUT_WARNING: &str = "cdp.target_setup_timeout";

pub(crate) fn cdp_records_method(method: &str) -> bool {
    method.starts_with("Network.") || CDP_TARGET_METHODS.contains(&method)
}

#[derive(Debug, Clone)]
pub(crate) struct AttachedTarget {
    pub(crate) session_id: String,
    pub(crate) target_id: String,
    pub(crate) target_type: String,
}

pub(crate) struct Cdp {
    pub(crate) next_id: u64,
    pub(crate) page_session_id: String,
    pub(crate) events: Vec<String>,
    pub(crate) status: Arc<Mutex<CaptureStatus>>,
    pub(crate) bodies_by_session: HashMap<String, BodyCollector>,
    pub(crate) bodies_file: std::fs::File,
    pub(crate) in_flight: HashMap<u64, (String, BodyTag)>,
    pub(crate) outbox: Vec<(String, String)>,
    pub(crate) setup_done: HashMap<String, AttachedTarget>,
    /// Sessions that already went through `setup_attached_target` (commands sent).
    pub(crate) configured_sessions: std::collections::HashSet<String>,
    pub(crate) configured_target_primary: HashMap<String, String>,
    pub(crate) detached_sessions: std::collections::HashSet<String>,
    pub(crate) wait_for_debugger: bool,
    /// Targets seen via auto-attach (at any time), per session.
    pub(crate) setup_seen: HashMap<String, AttachedTarget>,
    /// Setup commands sent and still without a response, by CDP id. Setup
    /// never blocks: the response is handled by `record` in arrival order,
    /// by whoever is reading the socket.
    pub(crate) setup_pending: HashMap<u64, PendingSetupCommand>,
    /// `Page.loadEventFired` seen in the main page's session.
    pub(crate) page_load_events: u64,
    /// Successful ACKs of setup commands, by (session, method).
    pub(crate) setup_acked: std::collections::HashSet<(String, String)>,
    /// External `expose_cdp` commands in flight, by the id sent to Chrome.
    pub(crate) external: HashMap<u64, cdp_expose::ExternalPending>,
    /// Socket clients and the sessions each one attached.
    pub(crate) fanout: cdp_expose::ExternalFanout,
    /// Chrome command id → target id for an external `Target.attachToTarget`
    /// that has not been answered yet. The matching `Target.attachedToTarget`
    /// belongs to that client; capture must not detach it as a duplicate.
    pub(crate) external_attaches: HashMap<u64, String>,
}

/// Target setup command awaiting its ACK.
#[derive(Debug, Clone)]
pub(crate) struct PendingSetupCommand {
    target: AttachedTarget,
    method: String,
    sent_at: Instant,
    parent_session_id: Option<String>,
}

impl Cdp {
    pub(crate) fn new(status: Arc<Mutex<CaptureStatus>>, bodies_file: std::fs::File) -> Result<Self, String> {
        Ok(Self {
            next_id: 0,
            page_session_id: String::new(),
            events: Vec::new(),
            status,
            bodies_by_session: HashMap::new(),
            bodies_file: bodies_file
                .try_clone()
                .map_err(|error| format!("cdp-bodies.jsonl: {error}"))?,
            in_flight: HashMap::new(),
            outbox: Vec::new(),
            setup_done: HashMap::new(),
            configured_sessions: std::collections::HashSet::new(),
            configured_target_primary: HashMap::new(),
            detached_sessions: std::collections::HashSet::new(),
            wait_for_debugger: true,
            setup_seen: HashMap::new(),
            setup_pending: HashMap::new(),
            page_load_events: 0,
            setup_acked: std::collections::HashSet::new(),
            external: HashMap::new(),
            fanout: cdp_expose::ExternalFanout::default(),
            external_attaches: HashMap::new(),
        })
    }

    pub(crate) fn auto_attach_params(&self, wait_on_start: bool) -> Value {
        json!({
            "autoAttach": true,
            "flatten": true,
            "waitForDebuggerOnStart": wait_on_start && self.wait_for_debugger,
        })
    }

    pub(crate) fn wire_command(
        &mut self,
        socket: &mut Transport,
        method: &str,
        params: Value,
        session: Option<&str>,
    ) -> Result<u64, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        socket
            .send_text(message.to_string())
            .map_err(|error| format!("CDP send {method}: {error}"))?;
        Ok(id)
    }

    pub(crate) fn pump_socket(
        &mut self,
        socket: &mut Transport,
        window: Duration,
    ) {
        let deadline = Instant::now() + window;
        while Instant::now() < deadline {
            match socket.read() {
                Ok(Incoming::Text(text)) => {
                    if let Ok(value) = serde_json::from_str::<Value>(text.as_str()) {
                        self.record(socket, &value);
                        self.flush_outbox(socket);
                    }
                }
                Ok(Incoming::Ping(payload)) => {
                    socket.pong(payload);
                }
                Ok(Incoming::Close) | Ok(Incoming::Other) => break,
                Err(ReadError::WouldBlock) => {}
                Err(_) => break,
            }
        }
    }

    pub(crate) fn bodies_for(&mut self, session_id: &str) -> &mut BodyCollector {
        self.bodies_by_session
            .entry(session_id.to_string())
            .or_default()
    }

    /// Sends a setup command without waiting for the response, and records it as
    /// pending. A late response produces no warning: only what is still without an ACK
    /// at shutdown becomes `Capture.targetSetupTimeout`.
    pub(crate) fn wire_setup_command(
        &mut self,
        socket: &mut Transport,
        target: &AttachedTarget,
        method: &str,
        params: Value,
        parent_session_id: Option<&str>,
    ) -> Result<(), String> {
        let id = self.wire_command(socket, method, params, Some(&target.session_id))?;
        self.register_setup_command(id, target, method, parent_session_id);
        Ok(())
    }

    pub(crate) fn register_setup_command(
        &mut self,
        id: u64,
        target: &AttachedTarget,
        method: &str,
        parent_session_id: Option<&str>,
    ) {
        self.setup_pending.insert(
            id,
            PendingSetupCommand {
                target: target.clone(),
                method: method.to_string(),
                sent_at: Instant::now(),
                parent_session_id: parent_session_id.map(str::to_string),
            },
        );
    }

    /// Handles the ACK of a setup command. Returns `true` if the id was a setup one.
    /// A late ACK only removes the pending entry; an error on an essential command becomes
    /// `Capture.targetSetupError` (as opposed to "no response").
    pub(crate) fn on_setup_response(&mut self, id: u64, value: &Value) -> bool {
        let Some(pending) = self.setup_pending.remove(&id) else {
            return false;
        };
        if value.get("error").is_none() {
            self.setup_acked
                .insert((pending.target.session_id.clone(), pending.method.clone()));
        }
        if let Some(error) = value.get("error") {
            let text = error
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| error.to_string());
            let gone = text.contains("not found") || text.contains("Target closed");
            if gone {
                self.push_target_setup_aborted(&pending.target, pending.parent_session_id.as_deref());
            } else if matches!(
                pending.method.as_str(),
                "Network.enable" | "Target.setAutoAttach" | "Runtime.runIfWaitingForDebugger"
            ) {
                self.push_event_line(
                    &pending.target.session_id,
                    "Capture.targetSetupError",
                    &json!({
                        "targetId": pending.target.target_id,
                        "sessionId": pending.target.session_id,
                        "type": pending.target.target_type,
                        "command": pending.method,
                        "error": text,
                    }),
                    pending.parent_session_id.as_deref(),
                );
            }
        }
        true
    }

    /// Is our client attached to the initial target? (`Network.enable` and
    /// `Target.setAutoAttach` with a successful ACK, no setup command
    /// pending, and the session configured.) Error = what is still missing.
    pub(crate) fn initial_target_gate(&self) -> Result<(), String> {
        let page = &self.page_session_id;
        if page.is_empty() {
            return Err("the initial tab has not attached yet".to_string());
        }
        if !self.configured_sessions.contains(page) {
            return Err("the initial tab has not been configured yet".to_string());
        }
        if let Some(pending) = self.setup_pending.values().find(|p| &p.target.session_id == page) {
            return Err(format!("{} still awaiting a response on the initial tab", pending.method));
        }
        for method in ["Network.enable", "Target.setAutoAttach"] {
            if !self.setup_acked.contains(&(page.clone(), method.to_string())) {
                return Err(format!("{method} not confirmed on the initial tab"));
            }
        }
        Ok(())
    }

    /// Reads the socket until the gate opens or the deadline passes.
    pub(crate) fn wait_initial_target_ready(
        &mut self,
        socket: &mut Transport,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.initial_target_gate() {
                Ok(()) => return Ok(()),
                Err(reason) if Instant::now() >= deadline => return Err(reason),
                Err(_) => self.pump_socket(socket, Duration::from_millis(100)),
            }
        }
    }

    /// Target detached or destroyed: its pending commands do not turn into a timeout.
    pub(crate) fn on_target_gone(&mut self, session_id: Option<&str>, target_id: Option<&str>) {
        let gone: Vec<u64> = self
            .setup_pending
            .iter()
            .filter(|(_, p)| {
                session_id.is_some_and(|s| p.target.session_id == s)
                    || target_id.is_some_and(|t| p.target.target_id == t)
            })
            .map(|(id, _)| *id)
            .collect();
        let mut seen = std::collections::HashSet::new();
        for id in gone {
            if let Some(pending) = self.setup_pending.remove(&id) {
                if seen.insert(pending.target.session_id.clone()) {
                    self.push_target_setup_aborted(
                        &pending.target,
                        pending.parent_session_id.as_deref(),
                    );
                }
            }
        }
    }

    pub(crate) fn push_target_setup_aborted(
        &mut self,
        attached: &AttachedTarget,
        parent_session_id: Option<&str>,
    ) {
        self.push_event_line(
            &attached.session_id,
            "Capture.targetSetupAborted",
            &json!({
                "targetId": attached.target_id,
                "sessionId": attached.session_id,
                "type": attached.target_type,
                "reason": "target closed during setup",
            }),
            parent_session_id,
        );
    }

    /// Shutdown (before `Browser.close`): every setup command still without an
    /// ACK, in any session (including the primary one), becomes a real warning.
    pub(crate) fn finalize_pending_setups(&mut self) {
        let mut pending: Vec<(u64, PendingSetupCommand)> = self.setup_pending.drain().collect();
        pending.sort_by_key(|(id, _)| *id);
        for (_, p) in pending {
            self.push_event_line(
                &p.target.session_id,
                "Capture.targetSetupTimeout",
                &json!({
                    "targetId": p.target.target_id,
                    "sessionId": p.target.session_id,
                    "type": p.target.target_type,
                    "command": p.method,
                    "pendingMs": p.sent_at.elapsed().as_millis() as u64,
                    "warningCode": CDP_TARGET_SETUP_TIMEOUT_WARNING,
                }),
                p.parent_session_id.as_deref(),
            );
        }
    }

    /// Reads the socket until no setup is pending or `window` runs out.
    pub(crate) fn pump_until_setup_settled(
        &mut self,
        socket: &mut Transport,
        window: Duration,
    ) {
        let deadline = Instant::now() + window;
        while !self.setup_pending.is_empty() && Instant::now() < deadline {
            self.pump_socket(socket, Duration::from_millis(100));
        }
    }

    pub(crate) fn push_event_line(
        &mut self,
        session_id: &str,
        method: &str,
        params: &Value,
        parent_session_id: Option<&str>,
    ) {
        let mut line = json!({
            "sessionId": session_id,
            "method": method,
            "params": params,
        });
        if let Some(parent) = parent_session_id.filter(|p| !p.is_empty() && *p != session_id) {
            line["parentSessionId"] = json!(parent);
        }
        self.events.push(line.to_string());
        if let Ok(mut guard) = self.status.lock() {
            guard.events = self.events.len();
        }
    }

    pub(crate) fn skip_target_setup(target_type: &str) -> bool {
        matches!(target_type, "browser_ui" | "other")
    }

    pub(crate) fn recurse_auto_attach(target_type: &str) -> bool {
        matches!(
            target_type,
            "page" | "iframe" | "worker" | "service_worker"
        )
    }

    pub(crate) fn setup_duplicate_target_session(
        &mut self,
        socket: &mut Transport,
        attached: AttachedTarget,
        waiting_for_debugger: bool,
        parent_session_id: Option<&str>,
    ) -> Result<(), String> {
        // Extra session of the same target: resumes it (if paused) and detaches, without network.
        // The ACKs do not matter: nothing here is capture setup.
        if self.wait_for_debugger && waiting_for_debugger {
            self.wire_command(
                socket,
                "Runtime.runIfWaitingForDebugger",
                json!({}),
                Some(&attached.session_id),
            )?;
        }
        self.wire_command(
            socket,
            "Target.detachFromTarget",
            json!({ "sessionId": attached.session_id }),
            None,
        )?;
        self.detached_sessions.insert(attached.session_id.clone());
        self.configured_sessions
            .insert(attached.session_id.clone());
        self.push_event_line(
            &attached.session_id,
            "Capture.sessionSetup",
            &json!({
                "targetId": attached.target_id,
                "type": attached.target_type,
                "waitingForDebugger": waiting_for_debugger,
                "duplicateSession": true,
                "detached": true,
            }),
            parent_session_id,
        );
        Ok(())
    }

    /// Configures an attached target without blocking: sends the commands in a pipeline,
    /// in the same session, and leaves the ACKs for whoever reads the socket (`record`).
    /// Paused target: Network.enable → Page/Runtime.enable → setAutoAttach →
    /// runIfWaitingForDebugger (the network is already on when it resumes, and the
    /// resume does not wait for a response). Unpaused target: the harness order
    /// (setAutoAttach → Network.enable → Page/Runtime.enable).
    pub(crate) fn setup_attached_target(
        &mut self,
        socket: &mut Transport,
        attached: AttachedTarget,
        waiting_for_debugger: bool,
        parent_session_id: Option<&str>,
    ) -> Result<(), String> {
        match self.configured_target_primary.get(&attached.target_id) {
            Some(primary) if primary != &attached.session_id => {
                return self.setup_duplicate_target_session(
                    socket,
                    attached,
                    waiting_for_debugger,
                    parent_session_id,
                );
            }
            None if !Self::skip_target_setup(&attached.target_type) => {
                self.configured_target_primary.insert(
                    attached.target_id.clone(),
                    attached.session_id.clone(),
                );
            }
            _ => {}
        }
        if self.configured_sessions.contains(&attached.session_id) {
            return Ok(());
        }
        // Mark before sending: avoids re-entry if the send fails.
        self.configured_sessions
            .insert(attached.session_id.clone());
        self.setup_seen
            .insert(attached.session_id.clone(), attached.clone());
        let target_type = attached.target_type.clone();
        let resume = self.wait_for_debugger && waiting_for_debugger;
        if Self::skip_target_setup(&target_type) {
            if resume {
                self.wire_command(
                    socket,
                    "Runtime.runIfWaitingForDebugger",
                    json!({}),
                    Some(&attached.session_id),
                )?;
            }
            self.setup_done
                .insert(attached.session_id.clone(), attached.clone());
            self.push_event_line(
                &attached.session_id,
                "Capture.sessionSetup",
                &json!({
                    "targetId": attached.target_id,
                    "type": target_type,
                    "waitingForDebugger": waiting_for_debugger,
                    "resumedDebugger": resume,
                    "skippedNetwork": true,
                }),
                parent_session_id,
            );
            return Ok(());
        }
        let network_params = json!({
            "maxTotalBufferSize": 100_000_000,
            "maxResourceBufferSize": 50_000_000,
            "maxPostDataSize": MAX_BODY_BYTES
        });
        let recurse = Self::recurse_auto_attach(&target_type);
        let page_like = target_type == "page" || target_type == "iframe";
        let parent = parent_session_id;
        let auto_attach = self.auto_attach_params(true);
        let mut commands: Vec<(&str, Value)> = Vec::new();
        if resume {
            commands.push(("Network.enable", network_params));
            if page_like {
                commands.push(("Page.enable", json!({})));
            }
            commands.push(("Runtime.enable", json!({})));
            if recurse {
                commands.push(("Target.setAutoAttach", auto_attach));
            }
            commands.push(("Runtime.runIfWaitingForDebugger", json!({})));
        } else {
            if recurse {
                commands.push(("Target.setAutoAttach", auto_attach));
            }
            commands.push(("Network.enable", network_params));
            if page_like {
                commands.push(("Page.enable", json!({})));
            }
            commands.push(("Runtime.enable", json!({})));
        }
        for (method, params) in commands {
            self.wire_setup_command(socket, &attached, method, params, parent)?;
        }
        self.setup_done
            .insert(attached.session_id.clone(), attached.clone());
        self.push_event_line(
            &attached.session_id,
            "Capture.sessionSetup",
            &json!({
                "targetId": attached.target_id,
                "type": target_type,
                "waitingForDebugger": waiting_for_debugger,
                "resumedDebugger": resume,
                "pipelinedSetup": true,
                "recursiveAutoAttach": recurse,
            }),
            parent_session_id,
        );
        Ok(())
    }

    pub(crate) fn session_for_recorded_event(
        &self,
        method: &str,
        wire: &Value,
        params: &Value,
    ) -> String {
        if method == "Target.attachedToTarget" {
            return params
                .get("sessionId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
        }
        if method == "Target.targetInfoChanged" {
            if let Some(target_id) = params
                .get("targetInfo")
                .and_then(|info| info.get("targetId"))
                .and_then(Value::as_str)
            {
                for attached in self.setup_done.values().chain(self.setup_seen.values()) {
                    if attached.target_id == target_id {
                        return attached.session_id.clone();
                    }
                }
            }
        }
        wire
            .get("sessionId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    pub(crate) fn handle_incoming_event(
        &mut self,
        socket: &mut Transport,
        value: &Value,
    ) {
        let Some(method) = value.get("method").and_then(Value::as_str) else {
            return;
        };
        if method == "Target.detachedFromTarget" {
            let session_id = value
                .get("params")
                .and_then(|p| p.get("sessionId"))
                .and_then(Value::as_str);
            self.on_target_gone(session_id, None);
        }
        if method == "Page.loadEventFired"
            && !self.page_session_id.is_empty()
            && value.get("sessionId").and_then(Value::as_str) == Some(self.page_session_id.as_str())
        {
            self.page_load_events += 1;
        }
        if method == "Target.targetDestroyed" {
            let target_id = value
                .get("params")
                .and_then(|p| p.get("targetId"))
                .and_then(Value::as_str);
            self.on_target_gone(None, target_id);
        }
        if method == "Target.attachedToTarget" {
            if let Some(params) = value.get("params").and_then(Value::as_object) {
                let session_id = params
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let target = params.get("targetInfo").and_then(Value::as_object);
                let target_id = target
                    .and_then(|t| t.get("targetId"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let target_type = target
                    .and_then(|t| t.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let waiting = params
                    .get("waitingForDebugger")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let attached = AttachedTarget {
                    session_id: session_id.clone(),
                    target_id: target_id.clone(),
                    target_type: target_type.clone(),
                };
                let parent_wire = value.get("sessionId").and_then(Value::as_str);
                // A socket client's own attach. Configuring it would see the capture
                // session as primary and detach the client (`setup_duplicate_target_session`).
                let client_attach = self.fanout.owns_session(&session_id)
                    || self
                        .external_attaches
                        .values()
                        .any(|pending| pending == &target_id);
                if !client_attach {
                    if !Self::skip_target_setup(&target_type) {
                        self.configured_target_primary
                            .entry(target_id.clone())
                            .or_insert(session_id.clone());
                    }
                    self.setup_seen
                        .insert(session_id.clone(), attached.clone());
                    // Does not block: it only sends the commands. A send failure (socket)
                    // shows up as a read error in the capture loop.
                    let _ = self.setup_attached_target(socket, attached, waiting, parent_wire);
                }
            }
        }
        if !cdp_records_method(method) {
            return;
        }
        let params = value.get("params").cloned().unwrap_or(Value::Null);
        let session_id = self.session_for_recorded_event(method, value, &params);
        if method.starts_with("Network.") && self.detached_sessions.contains(&session_id) {
            return;
        }
        let parent_session_id = if method == "Target.attachedToTarget" {
            value.get("sessionId").and_then(Value::as_str)
        } else {
            None
        };
        self.push_event_line(&session_id, method, &params, parent_session_id);
        if method.starts_with("Network.") {
            for command in self.bodies_for(&session_id).on_event(method, &params) {
                let id = self.next_id;
                self.next_id += 1;
                let message =
                    json!({ "id": id, "method": command.method, "params": command.params });
                self.in_flight
                    .insert(id, (session_id.clone(), command.tag));
                self.outbox
                    .push((session_id.clone(), message.to_string()));
            }
            self.write_body_lines();
        }
    }

    pub(crate) fn setup(
        &mut self,
        socket: &mut Transport,
        start_url: &str,
        cookies: &[cookies::ImportedCookie],
        audit: Option<CookieAudit<'_>>,
    ) -> Result<(), String> {
        let setup_result = self.setup_inner(socket, start_url, cookies, audit);
        if setup_result.is_ok() {
            self.pump_socket(socket, Duration::from_millis(400));
        }
        setup_result
    }

    /// Recipe `cdp_multi_capture.mjs` (da972ef): root auto-attach, a setup queue
    /// per session, recursive `setAutoAttach` on the page before navigating.
    pub(crate) fn setup_inner(
        &mut self,
        socket: &mut Transport,
        start_url: &str,
        cookies: &[cookies::ImportedCookie],
        audit: Option<CookieAudit<'_>>,
    ) -> Result<(), String> {
        self.send(
            socket,
            "Target.setDiscoverTargets",
            json!({ "discover": true }),
            None,
            // Aligned with `wait_for_devtools` and `Target.setAutoAttach`: a cold headful Chrome
            // on macOS can take >10 s to initialize the GPU and the
            // window before draining fd 3 of the pipe (timeout seen by the user).
            Duration::from_secs(25),
        )?;
        self.send(
            socket,
            "Target.setAutoAttach",
            self.auto_attach_params(true),
            None,
            Duration::from_secs(25),
        )?;
        let url = if start_url.trim().is_empty() {
            "about:blank".to_string()
        } else {
            start_url.to_string()
        };
        let created = self.send(
            socket,
            "Target.createTarget",
            json!({ "url": "about:blank" }),
            None,
            Duration::from_secs(15),
        )?;
        let main_target = created
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| "CDP returned no targetId".to_string())?
            .to_string();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Some(page_session) = self
                .setup_seen
                .values()
                .find(|t| t.target_id == main_target && t.target_type == "page")
                .map(|t| t.session_id.clone())
            {
                self.page_session_id = page_session.clone();
                if !self.configured_sessions.contains(&page_session) {
                    // The handler normally already configured the page on attach;
                    // this branch only covers an attach that the handler did not see.
                    self.setup_attached_target(
                        socket,
                        AttachedTarget {
                            session_id: page_session.clone(),
                            target_id: main_target.clone(),
                            target_type: "page".to_string(),
                        },
                        false,
                        None,
                    )?;
                }
                self.send(
                    socket,
                    "Target.setAutoAttach",
                    self.auto_attach_params(true),
                    Some(&page_session),
                    Duration::from_secs(15),
                )?;
                self.send(
                    socket,
                    "Network.setCacheDisabled",
                    json!({ "cacheDisabled": true }),
                    Some(&page_session),
                    Duration::from_secs(5),
                )?;
                if url != "about:blank" {
                    // Imported cookies are added BEFORE the first navigation: the
                    // initial request already carries the site's session.
                    if !cookies.is_empty() {
                        self.send(
                            socket,
                            "Network.setCookies",
                            json!({ "cookies": cookies::cdp_cookies(cookies) }),
                            Some(&page_session),
                            Duration::from_secs(10),
                        )?;
                    }
                    if let Some(audit) = audit {
                        self.push_event_line(
                            &page_session,
                            "Capture.cookiesImported",
                            &json!({
                                "source": audit.source,
                                "domain": audit.domain,
                                "importedCount": cookies.len(),
                                "skippedCount": audit.skipped,
                                "undecryptableCount": audit.undecryptable,
                                "undecryptableReason": audit.undecryptable_reason,
                            }),
                            None,
                        );
                    }
                    self.send(
                        socket,
                        "Page.navigate",
                        json!({ "url": url }),
                        Some(&page_session),
                        Duration::from_secs(30),
                    )?;
                }
                break;
            }
            self.pump_socket(socket, Duration::from_millis(100));
        }
        if self.page_session_id.is_empty() {
            return Err(
                "The initial page did not attach after createTarget (Target.attachedToTarget)"
                    .to_string(),
            );
        }
        let settle = Instant::now() + Duration::from_secs(5);
        while Instant::now() < settle {
            self.pump_socket(socket, Duration::from_millis(100));
        }
        Ok(())
    }

    pub(crate) fn send(
        &mut self,
        socket: &mut Transport,
        method: &str,
        params: Value,
        session: Option<&str>,
        timeout: Duration,
    ) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        socket
            .send_text(message.to_string())
            .map_err(|error| format!("CDP send {method}: {error}"))?;
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(format!("{} {method}", browser::CDP_TIMEOUT_PREFIX));
            }
            match socket.read() {
                Ok(Incoming::Text(text)) => {
                    let value: Value = serde_json::from_str(text.as_str())
                        .map_err(|error| format!("invalid CDP JSON: {error}"))?;
                    if value.get("id").and_then(Value::as_u64) == Some(id) {
                        if let Some(error) = value.get("error") {
                            return Err(format!("CDP {method}: {error}"));
                        }
                        return Ok(value.get("result").cloned().unwrap_or(Value::Null));
                    }
                    self.record(socket, &value);
                    self.flush_outbox(socket);
                }
                Ok(Incoming::Ping(payload)) => {
                    socket.pong(payload);
                }
                Ok(Incoming::Close) => return Err(format!("CDP fechou durante {method}")),
                Ok(_) => {}
                Err(ReadError::WouldBlock) => {}
                Err(ReadError::Fatal(error)) => return Err(format!("CDP read {method}: {error}")),
            }
        }
    }

    pub(crate) fn record(
        &mut self,
        socket: &mut Transport,
        value: &Value,
    ) {
        if let Some(id) = value.get("id").and_then(Value::as_u64) {
            self.external_attaches.remove(&id);
        }
        if cdp_expose::claim_external(&mut self.fanout, &mut self.external, value) {
            return;
        }
        if let Some(id) = value.get("id").and_then(Value::as_u64) {
            if self.on_setup_response(id, value) {
                return;
            }
            if let Some((session_id, tag)) = self.in_flight.remove(&id) {
                let outcome = match value.get("error") {
                    Some(error) => Err(error
                        .get("message")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| error.to_string())),
                    None => Ok(value.get("result").cloned().unwrap_or(Value::Null)),
                };
                self.bodies_for(&session_id).on_result(tag, outcome);
                self.write_body_lines();
            }
            return;
        }
        self.fanout.forward_event(value);
        self.handle_incoming_event(socket, value);
    }

    /// Sends, without waiting for a response, the body commands queued by
    /// `record`. A send failure becomes `unavailable` immediately.
    pub(crate) fn flush_outbox(&mut self, socket: &mut Transport) {
        for (session_id, message) in std::mem::take(&mut self.outbox) {
            let id = serde_json::from_str::<Value>(&message)
                .ok()
                .and_then(|value| value.get("id").and_then(Value::as_u64));
            let mut payload: Value = serde_json::from_str(&message).unwrap_or(Value::Null);
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("sessionId".to_string(), json!(session_id));
            }
            let wire = payload.to_string();
            if let Err(error) = socket.send_text(wire) {
                if let Some(id) = id {
                    if let Some((sid, tag)) = self.in_flight.remove(&id) {
                        self.bodies_for(&sid).on_result(
                            tag,
                            Err(format!("failed to send command to CDP: {error}")),
                        );
                    }
                }
            }
        }
        self.write_body_lines();
    }

    /// Waits (up to `window`) for the body responses still in flight.
    pub(crate) fn drain_bodies(
        &mut self,
        socket: &mut Transport,
        window: Duration,
    ) {
        let deadline = Instant::now() + window;
        while !self.in_flight.is_empty() && Instant::now() < deadline {
            match socket.read() {
                Ok(Incoming::Text(text)) => {
                    if let Ok(value) = serde_json::from_str::<Value>(text.as_str()) {
                        self.record(socket, &value);
                        self.flush_outbox(socket);
                    }
                }
                Ok(Incoming::Ping(payload)) => {
                    socket.pong(payload);
                }
                Ok(Incoming::Close) => break,
                Ok(_) => {}
                Err(ReadError::WouldBlock) => {}
                Err(_) => break,
            }
        }
    }

    /// Closes collection: nothing is left without a row.
    pub(crate) fn finish_bodies(&mut self) {
        let leftover: Vec<(String, BodyTag)> =
            self.in_flight.drain().map(|(_, pair)| pair).collect();
        for (session_id, tag) in leftover {
            self.bodies_for(&session_id).on_result(
                tag,
                Err("capture ended before CDP answered the body command".to_string()),
            );
        }
        for collector in self.bodies_by_session.values_mut() {
            collector.finish();
        }
        self.write_body_lines();
        let _ = self.bodies_file.sync_all();
    }

    pub(crate) fn write_body_lines(&mut self) {
        for (session_id, collector) in &mut self.bodies_by_session {
            for line in collector.take_lines() {
                let mut value: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                if let Some(map) = value.as_object_mut() {
                    map.insert("sessionId".to_string(), json!(session_id));
                }
                let out = format!("{value}\n");
                let result = self
                    .bodies_file
                    .write_all(out.as_bytes());
                if let Err(error) = result {
                    if let Ok(mut guard) = self.status.lock() {
                        guard.last_error = Some(format!("cdp-bodies.jsonl: {error}"));
                    }
                }
            }
        }
    }

    pub(crate) fn events_text(&self) -> String {
        if self.events.is_empty() {
            return String::new();
        }
        let mut text = self.events.join("\n");
        text.push('\n');
        text
    }
}

