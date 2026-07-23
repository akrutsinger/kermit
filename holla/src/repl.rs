//! Top-level REPL state, passed to every command.

use crate::session::{Note, Session};
use rustyline::DefaultEditor;
use std::sync::mpsc::Sender;

pub struct Repl {
    pub rl: DefaultEditor,
    pub sessions: Vec<Session>,
    /// Session that `ls` and friends act on; `None` at the top level.
    pub active: Option<u32>,
    pub src_ip: Option<String>,
    pub next_id: u32,
    /// History for the top-level prompt.
    base_history: Vec<String>,
    /// Cloned into each worker's `Notifier`.
    pub notes: Sender<Note>,
}

impl Repl {
    pub fn new(rl: DefaultEditor, notes: Sender<Note>) -> Self {
        Repl {
            rl,
            sessions: Vec::new(),
            active: None,
            src_ip: None,
            next_id: 1,
            base_history: Vec::new(),
            notes,
        }
    }

    /// The currently selected session, if any.
    pub fn active(&self) -> Option<&Session> {
        let id = self.active?;
        self.sessions.iter().find(|s| s.id == id)
    }

    /// Prompt string for the active session.
    pub fn prompt(&self) -> String {
        match self.active() {
            Some(s) => format!("holla({}:{})> ", s.id, s.label),
            None => "holla> ".into(),
        }
    }

    /// Add a line to the editor's recall and the active context's own history.
    pub fn record(&mut self, line: &str) {
        let _ = self.rl.add_history_entry(line);
        let history = match self.active {
            // active id always names a live session.
            Some(id) => {
                &mut self
                    .sessions
                    .iter_mut()
                    .find(|s| s.id == id)
                    .unwrap()
                    .history
            }
            None => &mut self.base_history,
        };
        history.push(line.to_owned());
    }

    /// Point the editor's recall buffer at `target`'s history. Call after switching context.
    pub fn reload_history(&mut self, target: Option<u32>) {
        let lines: Vec<String> = match target {
            Some(id) => self
                .sessions
                .iter()
                .find(|s| s.id == id)
                .map(|s| s.history.clone())
                .unwrap_or_default(),
            None => self.base_history.clone(),
        };
        let _ = self.rl.clear_history();
        for line in &lines {
            let _ = self.rl.add_history_entry(line.as_str());
        }
    }
}
