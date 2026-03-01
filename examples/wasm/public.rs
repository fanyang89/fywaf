use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
struct Request {
    client_ip: String,
    method: String,
    path: String,
    query: Option<String>,
    user_agent: Option<String>,
    headers: HashMap<String, String>,
    body: Option<String>,
}

#[derive(Serialize)]
struct Decision {
    allow: bool,
    status: u16,
    message: Option<String>,
    rule_id: Option<String>,
}

static mut RESULT_BUF: [u8; 65536] = [0; 65536];

#[no_mangle]
pub extern "C" fn decide(req_ptr: *const u8, req_len: usize) -> i32 {
    let req_slice = unsafe { std::slice::from_raw_parts(req_ptr, req_len) };
    let req_json = match std::str::from_utf8(req_slice) {
        Ok(s) => s,
        Err(_) => {
            return write_result(&Decision {
                allow: true,
                status: 200,
                message: None,
                rule_id: None,
            })
        }
    };

    let req: Request = match serde_json::from_str(req_json) {
        Ok(r) => r,
        Err(_) => {
            return write_result(&Decision {
                allow: true,
                status: 200,
                message: None,
                rule_id: None,
            })
        }
    };

    let decision = evaluate_request(&req);
    write_result(&decision)
}

fn evaluate_request(req: &Request) -> Decision {
    if req.path.contains("/admin") && !req.path.contains("/admin/public") {
        return Decision {
            allow: false,
            status: 403,
            message: Some("Admin access blocked".to_string()),
            rule_id: Some("block-admin".to_string()),
        };
    }

    if let Some(ua) = &req.user_agent {
        let ua_lower = ua.to_lowercase();
        if ua_lower.contains("sqlmap") || ua_lower.contains("nmap") || ua_lower.contains("nikto") {
            return Decision {
                allow: false,
                status: 403,
                message: Some("Scanner detected".to_string()),
                rule_id: Some("block-scanner".to_string()),
            };
        }
    }

    if let Some(body) = &req.body {
        let body_lower = body.to_lowercase();
        if body_lower.contains("union select") || body_lower.contains("drop table") {
            return Decision {
                allow: false,
                status: 403,
                message: Some("SQL injection detected".to_string()),
                rule_id: Some("block-sqli".to_string()),
            };
        }
    }

    Decision {
        allow: true,
        status: 200,
        message: None,
        rule_id: None,
    }
}

fn write_result(decision: &Decision) -> i32 {
    let json = serde_json::to_string(decision).unwrap_or_default();
    let bytes = json.as_bytes();
    let len = bytes.len();

    unsafe {
        RESULT_BUF[..len].copy_from_slice(bytes);
    }

    len as i32
}

#[no_mangle]
pub extern "C" fn get_result_ptr() -> *const u8 {
    unsafe { RESULT_BUF.as_ptr() }
}
