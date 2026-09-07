use pam::Conversation;
use passkeyd_abi::utils::ConversationQuestion;
use std::sync::mpsc::{Receiver, Sender};

pub struct InteractiveConversation {
    pub question_tx: Sender<ConversationQuestion>,
    pub answer_rx: Receiver<String>,
}

impl Conversation for InteractiveConversation {
    fn info(&mut self, msg: &std::ffi::CStr) {
        let text = msg.to_string_lossy().into_owned();
        let _ = self.question_tx.send(ConversationQuestion::Info(text));
    }
    fn prompt_blind(&mut self, msg: &std::ffi::CStr) -> Result<std::ffi::CString, ()> {
        let text = msg.to_string_lossy().into_owned();
        self.question_tx
            .send(ConversationQuestion::SensitiveInput(text))
            .map_err(|_| ())?;
        let answer = self.answer_rx.recv().map_err(|_| ())?;

        std::ffi::CString::new(answer).map_err(|_| ())
    }
    fn prompt_echo(&mut self, msg: &std::ffi::CStr) -> Result<std::ffi::CString, ()> {
        let text = msg.to_string_lossy().into_owned();
        self.question_tx
            .send(ConversationQuestion::Input(text))
            .map_err(|_| ())?;
        let answer = self.answer_rx.recv().map_err(|_| ())?;

        std::ffi::CString::new(answer).map_err(|_| ())
    }
    fn error(&mut self, msg: &std::ffi::CStr) {
        let text = msg.to_string_lossy().into_owned();
        let _ = self.question_tx.send(ConversationQuestion::Error(text));
    }
}
