use std::sync::Arc;

use warpgate_core::recordings::RdpRecorder;

pub struct RecorderTap {
    recorder: Arc<RdpRecorder>,
}

impl RecorderTap {
    pub fn new(recorder: Arc<RdpRecorder>) -> Self {
        Self { recorder }
    }

    pub fn recorder(&self) -> &Arc<RdpRecorder> {
        &self.recorder
    }
}
