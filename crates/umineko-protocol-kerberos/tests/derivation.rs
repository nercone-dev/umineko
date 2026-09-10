use umineko_protocol_kerberos::KerberosKeyUsage;
use umineko_protocol_kerberos::helpers::{KerberosKey, KerberosKeyDerivation};

#[test]
fn well_known_constants_follow_rfc3961() {
    let usage = KerberosKeyUsage::AP_REQ_AUTHENTICATOR;
    assert_eq!(KerberosKeyDerivation::Checksum.constant(usage), [0x00, 0x00, 0x00, 0x0B, 0x99]);
    assert_eq!(KerberosKeyDerivation::Encryption.constant(usage), [0x00, 0x00, 0x00, 0x0B, 0xAA]);
    assert_eq!(KerberosKeyDerivation::Integrity.constant(usage), [0x00, 0x00, 0x00, 0x0B, 0x55]);
    assert_eq!(KerberosKeyDerivation::Encryption.constant(KerberosKeyUsage(0x0102_0304)), [0x01, 0x02, 0x03, 0x04, 0xAA]);
    assert_eq!(KerberosKeyDerivation::ALL.len(), 3);
}

#[test]
fn prf_and_string_to_key_constants_follow_rfc3961_and_rfc3962() {
    assert_eq!(KerberosKey::PRF_CONSTANT, &[0x70, 0x72, 0x66]);
    assert_eq!(KerberosKey::STRING_TO_KEY_CONSTANT, &[0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73]);
}
