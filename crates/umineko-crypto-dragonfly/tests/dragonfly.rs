use umineko_crypto_dh::DHGroup;
use umineko_crypto_dragonfly::DragonflyGroup;
use umineko_crypto_ecdh::ECDHCurve;

#[test]
fn groups_are_prime_curves_or_finite_fields_by_rfc8492() {
    let curves = [(DragonflyGroup::SECP256R1, ECDHCurve::SECP256R1), (DragonflyGroup::SECP384R1, ECDHCurve::SECP384R1), (DragonflyGroup::SECP521R1, ECDHCurve::SECP521R1), (DragonflyGroup::BRAINPOOLP256R1, ECDHCurve::BRAINPOOLP256R1), (DragonflyGroup::BRAINPOOLP384R1, ECDHCurve::BRAINPOOLP384R1), (DragonflyGroup::BRAINPOOLP512R1, ECDHCurve::BRAINPOOLP512R1)];
    for (group, curve) in curves {
        assert_eq!(group.ecdh(), Some(curve));
        assert_eq!(group.dh(), None);
        assert!(group.elliptic_curve());
        assert_eq!(group.as_str(), curve.as_str());
    }
    let fields = [(DragonflyGroup::FFDHE2048, DHGroup::FFDHE2048), (DragonflyGroup::FFDHE3072, DHGroup::FFDHE3072), (DragonflyGroup::FFDHE4096, DHGroup::FFDHE4096), (DragonflyGroup::FFDHE6144, DHGroup::FFDHE6144), (DragonflyGroup::FFDHE8192, DHGroup::FFDHE8192)];
    for (group, field) in fields {
        assert_eq!(group.dh(), Some(field));
        assert_eq!(group.ecdh(), None);
        assert!(!group.elliptic_curve());
        assert_eq!(group.as_str(), field.as_str());
    }
}
