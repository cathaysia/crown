use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "size.pest"]
pub struct SizeParser;

pub fn parse_size(size_str: &str) -> anyhow::Result<usize> {
    let pairs = SizeParser::parse(Rule::size_expr, size_str.trim())
        .map_err(|e| anyhow::anyhow!("Invalid size format: {}", e))?;

    for pair in pairs {
        if pair.as_rule() == Rule::size_expr {
            for inner_pair in pair.into_inner() {
                if inner_pair.as_rule() == Rule::size {
                    return parse_size_inner(inner_pair);
                }
            }
        }
    }

    Err(anyhow::anyhow!("Failed to parse size"))
}

fn parse_size_inner(pair: pest::iterators::Pair<Rule>) -> anyhow::Result<usize> {
    let mut number = 0.0;
    let mut unit_multiplier = 1;

    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::number => {
                number = inner_pair
                    .as_str()
                    .parse::<f64>()
                    .map_err(|_| anyhow::anyhow!("Invalid number"))?;
            }
            Rule::unit => {
                let unit_str = inner_pair.as_str().to_lowercase();
                unit_multiplier = match unit_str.as_str() {
                    "k" | "kb" => 1024,
                    "m" | "mb" => 1024 * 1024,
                    "g" | "gb" => 1024 * 1024 * 1024,
                    _ => return Err(anyhow::anyhow!("Unknown unit: {}", unit_str)),
                };
            }
            _ => {}
        }
    }

    Ok((number * unit_multiplier as f64) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("1k").unwrap(), 1024);
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("2m").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size("1g").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("1kb").unwrap(), 1024);
        assert_eq!(parse_size("1Kb").unwrap(), 1024);
        assert_eq!(parse_size("2mb").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size("1gb").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("2MB").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("1.5k").unwrap(), 1536);
        assert_eq!(parse_size(" 512 ").unwrap(), 512);

        assert!(parse_size("invalid").is_err());
        assert!(parse_size("1x").is_err());
    }
}
