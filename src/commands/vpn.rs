//! Composite VPN enable/disable: route + DNS as a unit.

use crate::commands::{dns, route};
use crate::protocol::{ServiceRequest, ServiceResponse};

/// Enable VPN: add route + optionally set DNS. Rolls back route on DNS failure.
pub fn enable_vpn(request: &ServiceRequest) -> ServiceResponse {
    let cidr = match &request.cidr {
        Some(c) => c,
        None => return ServiceResponse::err("enable_vpn requires cidr"),
    };
    let via = match &request.via {
        Some(v) => v,
        None => return ServiceResponse::err("enable_vpn requires via"),
    };

    // Step 1: Add route
    let route_resp = route::add_route(cidr, via);
    if !route_resp.success {
        return route_resp;
    }

    // Step 2: Set DNS (if provided)
    if let Some(dns_server) = &request.dns {
        let dns_resp = dns::set_dns(request.host_adapter.as_deref(), dns_server);
        if !dns_resp.success {
            // Rollback route on DNS failure
            let _ = route::remove_route(cidr);
            return ServiceResponse::err(format!(
                "VPN enable failed at DNS step: {}",
                dns_resp.message.unwrap_or_default()
            ));
        }
    }

    ServiceResponse::ok("VPN enabled")
}

/// Disable VPN: remove route + clear DNS. Best-effort (both attempted).
pub fn disable_vpn(request: &ServiceRequest) -> ServiceResponse {
    let mut errors: Vec<String> = Vec::new();

    // Step 1: Remove route (best-effort)
    if let Some(cidr) = &request.cidr {
        let resp = route::remove_route(cidr);
        if !resp.success {
            errors.push(format!("route: {}", resp.message.unwrap_or_default()));
        }
    }

    // Step 2: Clear DNS (best-effort)
    let dns_resp = dns::clear_dns(request.host_adapter.as_deref());
    if !dns_resp.success {
        errors.push(format!("dns: {}", dns_resp.message.unwrap_or_default()));
    }

    if errors.is_empty() {
        ServiceResponse::ok("VPN disabled")
    } else {
        ServiceResponse::ok(format!("VPN disabled (with warnings: {})", errors.join("; ")))
    }
}
