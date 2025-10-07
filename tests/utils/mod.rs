use anyhow::bail;

pub fn parse_response_line(line: &str) -> anyhow::Result<(String, Vec<u8>)> {
    let parts: Vec<String> = line.split("=").map(|v| v.trim().to_lowercase()).collect();
    match parts.as_slice() {
        [key] => Ok((key.to_string(), vec![])),
        [key, value] => {
            let key = key.to_owned();
            let value = value.to_owned();
            if value.is_empty() || value == "0" {
                return Ok((key, vec![]));
            }
            Ok((key, hex::decode(value)?))
        }
        _ => bail!("bad response line: {line}"),
    }
}
