use std::sync::Arc;

use base64::Engine;
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::time::Instant;
use warpgate_db_entities::Recording::RecordingKind;

use super::writer::RecordingWriter;
use super::{Error, Recorder, Result};

#[derive(Serialize)]
#[serde(tag = "type")]
enum RdpRecordingFrame {
    #[serde(rename = "header")]
    Header {
        version: u32,
        width: u32,
        height: u32,
        started_at: String,
        target: RdpRecordingTarget,
    },
    #[serde(rename = "screenshot")]
    Screenshot {
        t: u64,
        w: u32,
        h: u32,
        encoding: &'static str,
        data: String,
    },
    #[serde(rename = "input")]
    Input {
        t: u64,
        kind: String,
        payload: serde_json::Value,
    },
}

#[derive(Serialize)]
pub struct RdpRecordingTarget {
    pub name: String,
    pub host: String,
}

struct RdpRecorderInner {
    writer: RecordingWriter,
    started_at: Instant,
    last_frame_at: Option<Instant>,
}

pub struct RdpRecorder {
    inner: Arc<Mutex<RdpRecorderInner>>,
}

impl RdpRecorder {
    fn elapsed_ms(inner: &RdpRecorderInner) -> u64 {
        inner.started_at.elapsed().as_millis() as u64
    }

    async fn write_frame(inner: &RdpRecorderInner, frame: &RdpRecordingFrame) -> Result<()> {
        let mut serialized = serde_json::to_vec(frame).map_err(Error::Serialization)?;
        serialized.push(b'\n');
        inner.writer.write(&serialized).await?;
        Ok(())
    }

    pub async fn write_header(
        &self,
        width: u32,
        height: u32,
        target: RdpRecordingTarget,
    ) -> Result<()> {
        let inner = self.inner.lock().await;
        let frame = RdpRecordingFrame::Header {
            version: 1,
            width,
            height,
            started_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            target,
        };
        Self::write_frame(&inner, &frame).await
    }

    pub async fn write_screenshot(&self, width: u32, height: u32, png_data: &[u8]) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();

        if let Some(last) = inner.last_frame_at {
            if now.duration_since(last).as_millis() < 250 {
                return Ok(());
            }
        }

        let t = Self::elapsed_ms(&inner);
        let data = base64::engine::general_purpose::STANDARD.encode(png_data);
        let frame = RdpRecordingFrame::Screenshot {
            t,
            w: width,
            h: height,
            encoding: "png",
            data,
        };
        Self::write_frame(&inner, &frame).await?;
        inner.last_frame_at = Some(now);
        Ok(())
    }

    pub async fn write_key_input(&self, scancode: u32, down: bool, extended: bool) -> Result<()> {
        let inner = self.inner.lock().await;
        let t = Self::elapsed_ms(&inner);
        let frame = RdpRecordingFrame::Input {
            t,
            kind: "key".into(),
            payload: serde_json::json!({
                "scancode": scancode,
                "down": down,
                "extended": extended,
            }),
        };
        Self::write_frame(&inner, &frame).await
    }

    pub async fn write_mouse_input(&self, x: u16, y: u16, button: &str, down: bool) -> Result<()> {
        let inner = self.inner.lock().await;
        let t = Self::elapsed_ms(&inner);
        let frame = RdpRecordingFrame::Input {
            t,
            kind: "mouse".into(),
            payload: serde_json::json!({
                "x": x,
                "y": y,
                "button": button,
                "down": down,
            }),
        };
        Self::write_frame(&inner, &frame).await
    }

    pub async fn write_focus_event(&self, window: &str) -> Result<()> {
        let inner = self.inner.lock().await;
        let t = Self::elapsed_ms(&inner);
        let frame = RdpRecordingFrame::Input {
            t,
            kind: "focus".into(),
            payload: serde_json::json!({
                "window": window,
            }),
        };
        Self::write_frame(&inner, &frame).await
    }
}

impl Recorder for RdpRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Rdp
    }

    fn new(writer: RecordingWriter) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RdpRecorderInner {
                writer,
                started_at: Instant::now(),
                last_frame_at: None,
            })),
        }
    }
}
