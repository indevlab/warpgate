use tokio::sync::mpsc;

pub struct RDPSessionHandle {
    close_tx: mpsc::Sender<()>,
}

impl RDPSessionHandle {
    pub fn new() -> (Self, mpsc::Receiver<()>) {
        let (close_tx, close_rx) = mpsc::channel(1);
        (Self { close_tx }, close_rx)
    }
}

impl warpgate_core::SessionHandle for RDPSessionHandle {
    fn close(&mut self) {
        let _ = self.close_tx.try_send(());
    }
}
