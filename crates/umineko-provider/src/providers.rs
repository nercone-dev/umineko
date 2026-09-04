use alloc::{sync::Arc, vec::Vec};

use umineko_helpers::provider::{ProviderCategory, ProviderError, ProviderPolicy};
use crate::bundle::ProviderBundle;
#[cfg(feature = "ip")]
use umineko_protocol_ip::IPProviders;
#[cfg(feature = "icmp")]
use umineko_protocol_icmp::ICMPProviders;
#[cfg(feature = "uds")]
use umineko_protocol_uds::UDSProviders;
#[cfg(feature = "tcp")]
use umineko_protocol_tcp::TCPProviders;
#[cfg(feature = "udp")]
use umineko_protocol_udp::UDPProviders;
#[cfg(feature = "tls")]
use umineko_protocol_tls::TLSProviders;
#[cfg(feature = "quic")]
use umineko_protocol_quic::QUICProviders;
#[cfg(feature = "http")]
use umineko_protocol_http::HTTPProviders;
#[cfg(feature = "dns")]
use umineko_protocol_dns::DNSProviders;
#[cfg(feature = "hash")]
use umineko_helpers::provider::HashProviders;
#[cfg(feature = "crypto")]
use umineko_helpers::provider::CipherProviders;
#[cfg(feature = "crypto")]
use umineko_helpers::provider::SignatureProviders;
#[cfg(feature = "crypto")]
use umineko_helpers::provider::ExchangeProviders;
#[cfg(feature = "crypto")]
use umineko_helpers::provider::KDFProviders;
#[cfg(feature = "codec")]
use umineko_helpers::provider::CodecProviders;

pub struct Providers;

impl Providers {
    pub fn register<P: ProviderBundle + ?Sized + 'static>(provider: Arc<P>) -> Result<(), ProviderError> {
        if provider.name() == ProviderPolicy::BUILTIN || Self::registered(provider.name()) {
            return Err(ProviderError::Argument);
        }
        #[cfg(feature = "ip")]
        if let Some(provider) = provider.clone().ip() {
            IPProviders::global().register(provider)?;
        }
        #[cfg(feature = "icmp")]
        if let Some(provider) = provider.clone().icmp() {
            ICMPProviders::global().register(provider)?;
        }
        #[cfg(feature = "uds")]
        if let Some(provider) = provider.clone().uds() {
            UDSProviders::global().register(provider)?;
        }
        #[cfg(feature = "tcp")]
        if let Some(provider) = provider.clone().tcp() {
            TCPProviders::global().register(provider)?;
        }
        #[cfg(feature = "udp")]
        if let Some(provider) = provider.clone().udp() {
            UDPProviders::global().register(provider)?;
        }
        #[cfg(feature = "tls")]
        if let Some(provider) = provider.clone().tls() {
            TLSProviders::global().register(provider)?;
        }
        #[cfg(feature = "quic")]
        if let Some(provider) = provider.clone().quic() {
            QUICProviders::global().register(provider)?;
        }
        #[cfg(feature = "http")]
        if let Some(provider) = provider.clone().http() {
            HTTPProviders::global().register(provider)?;
        }
        #[cfg(feature = "dns")]
        if let Some(provider) = provider.clone().dns() {
            DNSProviders::global().register(provider)?;
        }
        #[cfg(feature = "hash")]
        if let Some(provider) = provider.clone().hash() {
            HashProviders::global().register(provider)?;
        }
        #[cfg(feature = "crypto")]
        if let Some(provider) = provider.clone().cipher() {
            CipherProviders::global().register(provider)?;
        }
        #[cfg(feature = "crypto")]
        if let Some(provider) = provider.clone().signature() {
            SignatureProviders::global().register(provider)?;
        }
        #[cfg(feature = "crypto")]
        if let Some(provider) = provider.clone().exchange() {
            ExchangeProviders::global().register(provider)?;
        }
        #[cfg(feature = "crypto")]
        if let Some(provider) = provider.clone().kdf() {
            KDFProviders::global().register(provider)?;
        }
        #[cfg(feature = "codec")]
        if let Some(provider) = provider.clone().codec() {
            CodecProviders::global().register(provider)?;
        }
        let _ = provider;
        Ok(())
    }

    pub fn unregister(name: &str) -> bool {
        let mut removed = false;
        #[cfg(feature = "ip")]
        {
            removed |= IPProviders::global().unregister(name);
        }
        #[cfg(feature = "icmp")]
        {
            removed |= ICMPProviders::global().unregister(name);
        }
        #[cfg(feature = "uds")]
        {
            removed |= UDSProviders::global().unregister(name);
        }
        #[cfg(feature = "tcp")]
        {
            removed |= TCPProviders::global().unregister(name);
        }
        #[cfg(feature = "udp")]
        {
            removed |= UDPProviders::global().unregister(name);
        }
        #[cfg(feature = "tls")]
        {
            removed |= TLSProviders::global().unregister(name);
        }
        #[cfg(feature = "quic")]
        {
            removed |= QUICProviders::global().unregister(name);
        }
        #[cfg(feature = "http")]
        {
            removed |= HTTPProviders::global().unregister(name);
        }
        #[cfg(feature = "dns")]
        {
            removed |= DNSProviders::global().unregister(name);
        }
        #[cfg(feature = "hash")]
        {
            removed |= HashProviders::global().unregister(name);
        }
        #[cfg(feature = "crypto")]
        {
            removed |= CipherProviders::global().unregister(name);
        }
        #[cfg(feature = "crypto")]
        {
            removed |= SignatureProviders::global().unregister(name);
        }
        #[cfg(feature = "crypto")]
        {
            removed |= ExchangeProviders::global().unregister(name);
        }
        #[cfg(feature = "crypto")]
        {
            removed |= KDFProviders::global().unregister(name);
        }
        #[cfg(feature = "codec")]
        {
            removed |= CodecProviders::global().unregister(name);
        }
        let _ = name;
        removed
    }

    pub fn registered(name: &str) -> bool {
        Self::names().contains(&name)
    }

    pub fn names() -> Vec<&'static str> {
        let mut names: Vec<&'static str> = Vec::new();
        #[cfg(feature = "ip")]
        for name in IPProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "icmp")]
        for name in ICMPProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "uds")]
        for name in UDSProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "tcp")]
        for name in TCPProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "udp")]
        for name in UDPProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "tls")]
        for name in TLSProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "quic")]
        for name in QUICProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "http")]
        for name in HTTPProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "dns")]
        for name in DNSProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "hash")]
        for name in HashProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "crypto")]
        for name in CipherProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "crypto")]
        for name in SignatureProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "crypto")]
        for name in ExchangeProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "crypto")]
        for name in KDFProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        #[cfg(feature = "codec")]
        for name in CodecProviders::global().names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        names
    }

    pub fn available(category: ProviderCategory) -> bool {
        match category {
        #[cfg(feature = "ip")]
            ProviderCategory::IP => !IPProviders::global().is_empty(),
        #[cfg(feature = "icmp")]
            ProviderCategory::ICMP => !ICMPProviders::global().is_empty(),
        #[cfg(feature = "uds")]
            ProviderCategory::UDS => !UDSProviders::global().is_empty(),
        #[cfg(feature = "tcp")]
            ProviderCategory::TCP => !TCPProviders::global().is_empty(),
        #[cfg(feature = "udp")]
            ProviderCategory::UDP => !UDPProviders::global().is_empty(),
        #[cfg(feature = "tls")]
            ProviderCategory::TLS => !TLSProviders::global().is_empty(),
        #[cfg(feature = "quic")]
            ProviderCategory::QUIC => !QUICProviders::global().is_empty(),
        #[cfg(feature = "http")]
            ProviderCategory::HTTP => !HTTPProviders::global().is_empty(),
        #[cfg(feature = "dns")]
            ProviderCategory::DNS => !DNSProviders::global().is_empty(),
        #[cfg(feature = "hash")]
            ProviderCategory::Hash => !HashProviders::global().is_empty(),
        #[cfg(feature = "crypto")]
            ProviderCategory::Cipher => !CipherProviders::global().is_empty(),
        #[cfg(feature = "crypto")]
            ProviderCategory::Signature => !SignatureProviders::global().is_empty(),
        #[cfg(feature = "crypto")]
            ProviderCategory::Exchange => !ExchangeProviders::global().is_empty(),
        #[cfg(feature = "crypto")]
            ProviderCategory::KDF => !KDFProviders::global().is_empty(),
        #[cfg(feature = "codec")]
            ProviderCategory::Codec => !CodecProviders::global().is_empty(),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    pub fn enabled(name: &str) -> Option<bool> {
        #[cfg(feature = "ip")]
        if let Some(enabled) = IPProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "icmp")]
        if let Some(enabled) = ICMPProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "uds")]
        if let Some(enabled) = UDSProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "tcp")]
        if let Some(enabled) = TCPProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "udp")]
        if let Some(enabled) = UDPProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "tls")]
        if let Some(enabled) = TLSProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "quic")]
        if let Some(enabled) = QUICProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "http")]
        if let Some(enabled) = HTTPProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "dns")]
        if let Some(enabled) = DNSProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "hash")]
        if let Some(enabled) = HashProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "crypto")]
        if let Some(enabled) = CipherProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "crypto")]
        if let Some(enabled) = SignatureProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "crypto")]
        if let Some(enabled) = ExchangeProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "crypto")]
        if let Some(enabled) = KDFProviders::global().enabled(name) {
            return Some(enabled);
        }
        #[cfg(feature = "codec")]
        if let Some(enabled) = CodecProviders::global().enabled(name) {
            return Some(enabled);
        }
        let _ = name;
        None
    }

    pub fn set_enabled(name: &str, enabled: bool) -> bool {
        let mut changed = false;
        #[cfg(feature = "ip")]
        {
            changed |= IPProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "icmp")]
        {
            changed |= ICMPProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "uds")]
        {
            changed |= UDSProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "tcp")]
        {
            changed |= TCPProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "udp")]
        {
            changed |= UDPProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "tls")]
        {
            changed |= TLSProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "quic")]
        {
            changed |= QUICProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "http")]
        {
            changed |= HTTPProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "dns")]
        {
            changed |= DNSProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "hash")]
        {
            changed |= HashProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "crypto")]
        {
            changed |= CipherProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "crypto")]
        {
            changed |= SignatureProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "crypto")]
        {
            changed |= ExchangeProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "crypto")]
        {
            changed |= KDFProviders::global().set_enabled(name, enabled);
        }
        #[cfg(feature = "codec")]
        {
            changed |= CodecProviders::global().set_enabled(name, enabled);
        }
        let _ = (name, enabled);
        changed
    }

    pub fn priority(name: &str) -> Option<i32> {
        #[cfg(feature = "ip")]
        if let Some(priority) = IPProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "icmp")]
        if let Some(priority) = ICMPProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "uds")]
        if let Some(priority) = UDSProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "tcp")]
        if let Some(priority) = TCPProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "udp")]
        if let Some(priority) = UDPProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "tls")]
        if let Some(priority) = TLSProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "quic")]
        if let Some(priority) = QUICProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "http")]
        if let Some(priority) = HTTPProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "dns")]
        if let Some(priority) = DNSProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "hash")]
        if let Some(priority) = HashProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "crypto")]
        if let Some(priority) = CipherProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "crypto")]
        if let Some(priority) = SignatureProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "crypto")]
        if let Some(priority) = ExchangeProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "crypto")]
        if let Some(priority) = KDFProviders::global().priority(name) {
            return Some(priority);
        }
        #[cfg(feature = "codec")]
        if let Some(priority) = CodecProviders::global().priority(name) {
            return Some(priority);
        }
        let _ = name;
        None
    }

    pub fn set_priority(name: &str, priority: i32) -> bool {
        let mut changed = false;
        #[cfg(feature = "ip")]
        {
            changed |= IPProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "icmp")]
        {
            changed |= ICMPProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "uds")]
        {
            changed |= UDSProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "tcp")]
        {
            changed |= TCPProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "udp")]
        {
            changed |= UDPProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "tls")]
        {
            changed |= TLSProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "quic")]
        {
            changed |= QUICProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "http")]
        {
            changed |= HTTPProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "dns")]
        {
            changed |= DNSProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "hash")]
        {
            changed |= HashProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "crypto")]
        {
            changed |= CipherProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "crypto")]
        {
            changed |= SignatureProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "crypto")]
        {
            changed |= ExchangeProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "crypto")]
        {
            changed |= KDFProviders::global().set_priority(name, priority);
        }
        #[cfg(feature = "codec")]
        {
            changed |= CodecProviders::global().set_priority(name, priority);
        }
        let _ = (name, priority);
        changed
    }

    pub fn policy(category: ProviderCategory) -> ProviderPolicy {
        match category {
        #[cfg(feature = "ip")]
            ProviderCategory::IP => IPProviders::global().policy(),
        #[cfg(feature = "icmp")]
            ProviderCategory::ICMP => ICMPProviders::global().policy(),
        #[cfg(feature = "uds")]
            ProviderCategory::UDS => UDSProviders::global().policy(),
        #[cfg(feature = "tcp")]
            ProviderCategory::TCP => TCPProviders::global().policy(),
        #[cfg(feature = "udp")]
            ProviderCategory::UDP => UDPProviders::global().policy(),
        #[cfg(feature = "tls")]
            ProviderCategory::TLS => TLSProviders::global().policy(),
        #[cfg(feature = "quic")]
            ProviderCategory::QUIC => QUICProviders::global().policy(),
        #[cfg(feature = "http")]
            ProviderCategory::HTTP => HTTPProviders::global().policy(),
        #[cfg(feature = "dns")]
            ProviderCategory::DNS => DNSProviders::global().policy(),
        #[cfg(feature = "hash")]
            ProviderCategory::Hash => HashProviders::global().policy(),
        #[cfg(feature = "crypto")]
            ProviderCategory::Cipher => CipherProviders::global().policy(),
        #[cfg(feature = "crypto")]
            ProviderCategory::Signature => SignatureProviders::global().policy(),
        #[cfg(feature = "crypto")]
            ProviderCategory::Exchange => ExchangeProviders::global().policy(),
        #[cfg(feature = "crypto")]
            ProviderCategory::KDF => KDFProviders::global().policy(),
        #[cfg(feature = "codec")]
            ProviderCategory::Codec => CodecProviders::global().policy(),
            #[allow(unreachable_patterns)]
            _ => ProviderPolicy::DEFAULT,
        }
    }

    pub fn set_policy(policy: ProviderPolicy) {
        #[cfg(feature = "ip")]
        {
            IPProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "icmp")]
        {
            ICMPProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "uds")]
        {
            UDSProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "tcp")]
        {
            TCPProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "udp")]
        {
            UDPProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "tls")]
        {
            TLSProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "quic")]
        {
            QUICProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "http")]
        {
            HTTPProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "dns")]
        {
            DNSProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "hash")]
        {
            HashProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "crypto")]
        {
            CipherProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "crypto")]
        {
            SignatureProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "crypto")]
        {
            ExchangeProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "crypto")]
        {
            KDFProviders::global().set_policy(policy.clone());
        }
        #[cfg(feature = "codec")]
        {
            CodecProviders::global().set_policy(policy.clone());
        }
        let _ = policy;
    }

    pub fn set_category_policy(category: ProviderCategory, policy: ProviderPolicy) -> bool {
        match category {
        #[cfg(feature = "ip")]
            ProviderCategory::IP => {
                IPProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "icmp")]
            ProviderCategory::ICMP => {
                ICMPProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "uds")]
            ProviderCategory::UDS => {
                UDSProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "tcp")]
            ProviderCategory::TCP => {
                TCPProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "udp")]
            ProviderCategory::UDP => {
                UDPProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "tls")]
            ProviderCategory::TLS => {
                TLSProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "quic")]
            ProviderCategory::QUIC => {
                QUICProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "http")]
            ProviderCategory::HTTP => {
                HTTPProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "dns")]
            ProviderCategory::DNS => {
                DNSProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "hash")]
            ProviderCategory::Hash => {
                HashProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "crypto")]
            ProviderCategory::Cipher => {
                CipherProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "crypto")]
            ProviderCategory::Signature => {
                SignatureProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "crypto")]
            ProviderCategory::Exchange => {
                ExchangeProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "crypto")]
            ProviderCategory::KDF => {
                KDFProviders::global().set_policy(policy);
                true
            }
        #[cfg(feature = "codec")]
            ProviderCategory::Codec => {
                CodecProviders::global().set_policy(policy);
                true
            }
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }
}
