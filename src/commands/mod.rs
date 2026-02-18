//! Command dispatcher and implementations for route, DNS, and VPN operations.

pub mod dns;
pub mod route;
pub mod vpn;

use crate::protocol::{ServiceRequest, ServiceResponse};

/// Dispatch a request to the appropriate command handler.
pub fn dispatch(request: &ServiceRequest) -> ServiceResponse {
    match request.action.as_str() {
        "add_route" => {
            let cidr = match &request.cidr {
                Some(c) => c,
                None => return ServiceResponse::err("Missing required field: cidr"),
            };
            let via = match &request.via {
                Some(v) => v,
                None => return ServiceResponse::err("Missing required field: via"),
            };
            route::add_route(cidr, via)
        }
        "remove_route" => {
            let cidr = match &request.cidr {
                Some(c) => c,
                None => return ServiceResponse::err("Missing required field: cidr"),
            };
            route::remove_route(cidr)
        }
        "update_route" => {
            let cidr = match &request.cidr {
                Some(c) => c,
                None => return ServiceResponse::err("Missing required field: cidr"),
            };
            let via = match &request.via {
                Some(v) => v,
                None => return ServiceResponse::err("Missing required field: via"),
            };
            route::update_route(cidr, via)
        }
        "set_dns" => {
            let dns_server = match &request.dns {
                Some(d) => d,
                None => return ServiceResponse::err("Missing required field: dns"),
            };
            let adapter = request.host_adapter.as_deref();
            dns::set_dns(adapter, dns_server)
        }
        "clear_dns" => {
            let adapter = request.host_adapter.as_deref();
            dns::clear_dns(adapter)
        }
        "enable_vpn" => vpn::enable_vpn(request),
        "disable_vpn" => vpn::disable_vpn(request),
        "status" => ServiceResponse::ok("Service is running"),
        other => ServiceResponse::err(format!("Unknown action: {}", other)),
    }
}
