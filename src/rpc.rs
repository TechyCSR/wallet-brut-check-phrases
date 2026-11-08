use serde_json::{json, Value};
use std::thread::sleep;
use std::time::Duration;

pub fn get_solana_balance(rpc_url: &str, address: &str) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address]
    });

    let resp: serde_json::Value = ureq::post(rpc_url)
        .header("Content-Type", "application/json")
        .send_json(payload)?
        .body_mut()
        .read_json()?;

    if let Some(err) = resp.get("error") {
        return Err(format!("RPC error: {}", err).into());
    }

    let lamports = resp["result"]["value"]
        .as_u64()
        .ok_or_else(|| format!("Invalid response format: {:?}", resp))?;

    Ok(lamports as f64 / 1_000_000_000.0)
}

/// Query multiple Solana addresses in a single JSON-RPC call using `getMultipleAccounts` (max 100 per call)
pub fn get_multiple_solana_balances_chunk(
    rpc_url: &str,
    addresses: &[&str],
) -> Result<Vec<f64>, Box<dyn std::error::Error + Send + Sync>> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getMultipleAccounts",
        "params": [
            addresses,
            { "encoding": "base64" }
        ]
    });

    let mut retries = 5;
    let mut backoff = Duration::from_millis(500);

    loop {
        let resp_res = ureq::post(rpc_url)
            .header("Content-Type", "application/json")
            .send_json(&payload);

        match resp_res {
            Ok(mut resp) => {
                let body: Value = resp.body_mut().read_json()?;
                if let Some(err) = body.get("error") {
                    let err_str = err.to_string();
                    if err_str.contains("429") || err_str.to_lowercase().contains("rate") {
                        if retries > 0 {
                            retries -= 1;
                            sleep(backoff);
                            backoff *= 2;
                            continue;
                        }
                    }
                    return Err(format!("RPC error: {}", err).into());
                }

                let values = body["result"]["value"]
                    .as_array()
                    .ok_or_else(|| format!("Invalid getMultipleAccounts response format: {:?}", body))?;

                let balances: Vec<f64> = values
                    .iter()
                    .map(|v| {
                        if v.is_null() {
                            0.0
                        } else {
                            v["lamports"].as_u64().unwrap_or(0) as f64 / 1_000_000_000.0
                        }
                    })
                    .collect();

                return Ok(balances);
            }
            Err(e) => {
                if retries > 0 {
                    retries -= 1;
                    sleep(backoff);
                    backoff *= 2;
                } else {
                    return Err(Box::new(e));
                }
            }
        }
    }
}

