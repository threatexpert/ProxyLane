//! RFC 8484: retain the HTTP exchange, annotate only validated DNS messages.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
fn header(message: &Value, name: &str) -> String {
    message["headers"].as_array().into_iter().flatten()
        .find(|h| h[0].as_str().is_some_and(|n| n.eq_ignore_ascii_case(name)))
        .and_then(|h| h[1].as_str()).unwrap_or("").to_ascii_lowercase()
}
fn dns_type(message: &Value) -> bool {
    header(message,"content-type").split(';').next().unwrap_or("").trim() == "application/dns-message"
}
fn get_query(target: &str) -> Option<Vec<u8>> {
    let query = target.split_once('?')?.1.split('#').next()?;
    let mut values = query.split('&').filter_map(|p|p.strip_prefix("dns="));
    let value = values.next()?;
    if values.next().is_some() || value.len() > 87380 { return None; }
    URL_SAFE_NO_PAD.decode(value).ok().filter(|v|v.len() <= 65535)
}
pub fn annotate(record: &mut Value) {
    if record["type"] != "exchange" { return; }
    let exchange = &record["exchange"];
    let request = &exchange["request"];
    let response = &exchange["response"];
    let method = request["method"].as_str().unwrap_or("");
    if method == "POST" && dns_type(request) || dns_type(response) {
        record["doh"] = json!({});
    }
    // A dns= parameter alone is not enough to classify an unrelated HTTP endpoint.
    let exchange = &record["exchange"];
    let request = &exchange["request"];
    if request["method"] == "GET" && (dns_type(&exchange["response"]) || header(request,"accept").split(',').any(|s|s.trim()=="application/dns-message")) {
        if let Some(bytes) = get_query(request["target"].as_str().unwrap_or("")) {
            if let Ok(packet) = proxylane_protocol::dns::decode(&bytes) {
                if !packet.response { record["doh"] = json!({"request_get":packet.text}); }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn get_post_and_unrelated_http() {
        let wire=[0,1,1,0,0,1,0,0,0,0,0,0,1,b'a',0,0,1,0,1];
        let mut get=json!({"type":"exchange","exchange":{"request":{"method":"GET","target":format!("/dns-query?dns={}",URL_SAFE_NO_PAD.encode(wire)),"headers":[["accept","application/dns-message"]]}}});
        annotate(&mut get); assert!(get["doh"]["request_get"].as_str().unwrap().contains("a."));
        get.as_object_mut().unwrap().remove("doh");get["exchange"]["request"]["headers"]=json!([]);annotate(&mut get);assert!(get.get("doh").is_none());
        let mut post=json!({"type":"exchange","exchange":{"request":{"method":"POST","headers":[["Content-Type","application/dns-message; charset=binary"]]}}});
        annotate(&mut post);assert!(post.get("doh").is_some());
        assert!(get_query("/dns?dns=AAAA&dns=BBBB").is_none());
        assert!(get_query("/dns?dns=%%%").is_none());
    }
}
