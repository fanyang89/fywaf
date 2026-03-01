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

const REQ_BUF_LEN: usize = 65536;
const RESULT_BUF_LEN: usize = 65536;
static mut REQ_BUF: [u8; REQ_BUF_LEN] = [0; REQ_BUF_LEN];
static mut RESULT_BUF: [u8; RESULT_BUF_LEN] = [0; RESULT_BUF_LEN];

/// Returns the address of the request buffer. The host writes the request JSON
/// here before calling `decide`.
#[no_mangle]
pub extern "C" fn get_req_ptr() -> *const u8 {
    unsafe { REQ_BUF.as_ptr() }
}

/// Called by the host with the byte length of the request JSON that was written
/// into the buffer returned by `get_req_ptr`. Returns the byte length of the
/// decision JSON written into `RESULT_BUF`.
#[no_mangle]
pub extern "C" fn decide(req_len: usize) -> i32 {
    let req_slice = unsafe { &REQ_BUF[..req_len.min(REQ_BUF_LEN)] };
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
    let copy_len = bytes.len().min(RESULT_BUF_LEN);

    unsafe {
        RESULT_BUF[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }

    copy_len as i32
}

/// Returns the address of the result buffer. The host reads `decide`'s return
/// value many bytes from this pointer to obtain the decision JSON.
#[no_mangle]
pub extern "C" fn get_result_ptr() -> *const u8 {
    unsafe { RESULT_BUF.as_ptr() }
}
