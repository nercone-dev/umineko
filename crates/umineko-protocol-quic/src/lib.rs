//! QUIC.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{QUICClient, QUICClientConfig};
    pub use server::{QUICServer, QUICServerConfig, QUICHandler};
}

pub mod helpers {
    pub mod congestion;
    pub mod loss;
    pub mod flow;
    pub mod handshake;

    pub use congestion::{QUICCongestion, QUICCongestionState};
    pub use loss::{QUICLossDetection, QUICPacketNumberSpace};
    pub use flow::{QUICFlowControl};
    pub use handshake::{QUICHandshake, QUICEncryptionLevel};
}

pub mod protocol {
    pub mod base;
    pub mod v1;
    pub mod v2;
    pub mod packet;
    pub mod frame;
    pub mod stream;

    pub use base::{QUICConnection};
    pub use v1::{QUICV1Connection};
    pub use v2::{QUICV2Connection};
    pub use packet::{QUICPacket, QUICPacketType, QUICPacketNumber};
    pub use frame::{QUICFrame, QUICFrameType};
    pub use stream::{QUICStream, QUICStreamState, QUICStreamKind};
}

pub mod errors;
pub mod types;
pub mod provider;

pub use errors::{QUICError, QUICTransportError};
pub use types::{QUICVersion, QUICRole, QUICConnectionID, QUICStreamID, QUICTransportParameters, QUICLimits};
pub use provider::{QUICProvider, QUICProviderRequest, QUICProviders};
