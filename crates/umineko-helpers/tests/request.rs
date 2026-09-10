use umineko_helpers::provider::{CipherProviderRequest, ExchangeProviderRequest};

#[test]
fn cipher_requests_leave_the_tag_size_to_the_algorithm_unless_given() {
    let request = CipherProviderRequest::new("AEGIS-128L", &[0; 16]);
    assert_eq!(request.tag_size, None);
    let request = request.with_tag_size(32);
    assert_eq!(request.tag_size, Some(32));
    assert_eq!(request.algorithm, "AEGIS-128L");
    assert_eq!(request.with_nonce(&[1; 16]).tag_size, Some(32));
}

#[test]
fn exchange_requests_keep_domain_parameters_and_context_apart() {
    let request = ExchangeProviderRequest::new("DH");
    assert_eq!((request.seed, request.parameters, request.context), (None, None, &[][..]));
    let request = request.with_parameters(b"parameters").with_context(b"context").with_seed(b"seed");
    assert_eq!(request.parameters, Some(&b"parameters"[..]));
    assert_eq!(request.context, b"context");
    assert_eq!(request.seed, Some(&b"seed"[..]));
}
