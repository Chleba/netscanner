use crate::action::Action;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

pub struct Network {
    action_tx: UnboundedSender<Action>,
    action_rx: UnboundedReceiver<Action>,
    t_handle: Option<JoinHandle<()>>,
}

impl Network {
    fn new(action_tx: UnboundedSender<Action>, action_rx: UnboundedReceiver<Action>) -> Self {
        let t_handle = thread::spawn(move || {
            Self::thread_net(action_tx.clone(), &action_rx);
        });

        Self {
            action_tx,
            action_rx,
            t_handle: Some(t_handle),
        }
    }

    fn thread_net(action_tx: UnboundedSender<Action>, ref action_rx: UnboundedReceiver<Action>) {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}
