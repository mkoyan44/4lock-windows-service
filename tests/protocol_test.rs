use fourlock_windows_service::protocol::{cidr_to_network_mask, ServiceRequest, ServiceResponse};

// --- ServiceRequest deserialization ---

#[test]
fn parse_add_route_all_fields() {
    let json = r#"{"action":"add_route","cidr":"10.35.0.0/16","via":"172.28.16.5","dns":"8.8.8.8","host_adapter":"Ethernet"}"#;
    let req: ServiceRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.action, "add_route");
    assert_eq!(req.cidr.as_deref(), Some("10.35.0.0/16"));
    assert_eq!(req.via.as_deref(), Some("172.28.16.5"));
    assert_eq!(req.dns.as_deref(), Some("8.8.8.8"));
    assert_eq!(req.host_adapter.as_deref(), Some("Ethernet"));
}

#[test]
fn parse_remove_route_minimal() {
    let json = r#"{"action":"remove_route","cidr":"10.35.0.0/16"}"#;
    let req: ServiceRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.action, "remove_route");
    assert_eq!(req.cidr.as_deref(), Some("10.35.0.0/16"));
    assert_eq!(req.via, None);
    assert_eq!(req.dns, None);
    assert_eq!(req.host_adapter, None);
}

#[test]
fn parse_enable_vpn() {
    let json = r#"{"action":"enable_vpn","cidr":"10.35.0.0/16","via":"172.28.16.5"}"#;
    let req: ServiceRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.action, "enable_vpn");
}

#[test]
fn parse_disable_vpn() {
    let json = r#"{"action":"disable_vpn","cidr":"10.35.0.0/16"}"#;
    let req: ServiceRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.action, "disable_vpn");
}

#[test]
fn parse_status() {
    let json = r#"{"action":"status"}"#;
    let req: ServiceRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.action, "status");
    assert_eq!(req.cidr, None);
}

#[test]
fn parse_set_dns() {
    let json = r#"{"action":"set_dns","dns":"8.8.8.8","host_adapter":"Wi-Fi"}"#;
    let req: ServiceRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.action, "set_dns");
    assert_eq!(req.dns.as_deref(), Some("8.8.8.8"));
    assert_eq!(req.host_adapter.as_deref(), Some("Wi-Fi"));
}

#[test]
fn parse_clear_dns() {
    let json = r#"{"action":"clear_dns","host_adapter":"Ethernet"}"#;
    let req: ServiceRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.action, "clear_dns");
}

// --- Invalid requests ---

#[test]
fn reject_empty_json() {
    let result = serde_json::from_str::<ServiceRequest>("{}");
    assert!(result.is_err());
}

#[test]
fn reject_malformed_json() {
    let result = serde_json::from_str::<ServiceRequest>("not json at all");
    assert!(result.is_err());
}

#[test]
fn reject_missing_action() {
    let json = r#"{"cidr":"10.0.0.0/8"}"#;
    let result = serde_json::from_str::<ServiceRequest>(json);
    assert!(result.is_err());
}

#[test]
fn reject_empty_string() {
    let result = serde_json::from_str::<ServiceRequest>("");
    assert!(result.is_err());
}

// --- ServiceResponse serialization ---

#[test]
fn serialize_ok_response() {
    let resp = ServiceResponse::ok("Route added");
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains(r#""success":true"#));
    assert!(json.contains(r#""message":"Route added""#));
}

#[test]
fn serialize_err_response() {
    let resp = ServiceResponse::err("Invalid CIDR");
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains(r#""success":false"#));
    assert!(json.contains(r#""message":"Invalid CIDR""#));
}

#[test]
fn serialize_response_no_message() {
    let resp = ServiceResponse {
        success: true,
        message: None,
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains(r#""success":true"#));
    // message field should be skipped entirely
    assert!(!json.contains("message"));
}

#[test]
fn response_round_trip() {
    let resp = ServiceResponse::ok("test message");
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: ServiceResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, deserialized);
}

// --- CIDR to network mask conversion ---

#[test]
fn cidr_slash_0() {
    let (net, mask) = cidr_to_network_mask("0.0.0.0/0").unwrap();
    assert_eq!(net, "0.0.0.0");
    assert_eq!(mask, "0.0.0.0");
}

#[test]
fn cidr_slash_8() {
    let (net, mask) = cidr_to_network_mask("10.0.0.0/8").unwrap();
    assert_eq!(net, "10.0.0.0");
    assert_eq!(mask, "255.0.0.0");
}

#[test]
fn cidr_slash_16() {
    let (net, mask) = cidr_to_network_mask("10.35.0.0/16").unwrap();
    assert_eq!(net, "10.35.0.0");
    assert_eq!(mask, "255.255.0.0");
}

#[test]
fn cidr_slash_24() {
    let (net, mask) = cidr_to_network_mask("192.168.1.0/24").unwrap();
    assert_eq!(net, "192.168.1.0");
    assert_eq!(mask, "255.255.255.0");
}

#[test]
fn cidr_slash_32() {
    let (net, mask) = cidr_to_network_mask("10.0.0.1/32").unwrap();
    assert_eq!(net, "10.0.0.1");
    assert_eq!(mask, "255.255.255.255");
}

#[test]
fn cidr_slash_17() {
    let (net, mask) = cidr_to_network_mask("172.16.0.0/17").unwrap();
    assert_eq!(net, "172.16.0.0");
    assert_eq!(mask, "255.255.128.0");
}

#[test]
fn cidr_invalid_no_slash() {
    assert!(cidr_to_network_mask("10.0.0.0").is_err());
}

#[test]
fn cidr_invalid_prefix_too_large() {
    assert!(cidr_to_network_mask("10.0.0.0/33").is_err());
}

#[test]
fn cidr_invalid_prefix_not_number() {
    assert!(cidr_to_network_mask("10.0.0.0/abc").is_err());
}

#[test]
fn cidr_invalid_network_address() {
    assert!(cidr_to_network_mask("999.0.0.0/8").is_err());
}

#[test]
fn cidr_invalid_too_few_octets() {
    assert!(cidr_to_network_mask("10.0.0/8").is_err());
}
