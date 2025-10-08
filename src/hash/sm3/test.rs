#[test]
fn test_sm3_openssl() {
    let content = include_str!("./evpmd_sm3.txt");
    let mut lines = content.lines();

    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("Digest = ") {
            let mut input = None;
            let mut output = None;

            for line in lines.by_ref() {
                let line = line.trim();
                if line.is_empty() {
                    break;
                }
                if line.starts_with('#') {
                    continue;
                }

                let (rkey, value) = parse_response_line(line);

                match rkey.as_str() {
                    "input" => {
                        input = Some(value);
                    }
                    "output" => {
                        output = Some(value);
                    }
                    _ => {
                        eprintln!("unexpected key: {rkey}");
                    }
                }
            }

            if let (Some(input), Some(output)) = (input, output) {
                let actual = super::sum_sm3(&input);

                assert_eq!(
                    &actual,
                    output.as_slice(),
                    "sm3 test failed for expected {}, got {}",
                    hex::encode(&output),
                    hex::encode(actual)
                );
            }
        }
    }
}

pub fn parse_response_line(line: &str) -> (String, Vec<u8>) {
    let x: Vec<_> = line.split("=").map(|v| v.trim().to_lowercase()).collect();
    match x.as_slice() {
        [key] => (key.to_owned(), vec![]),
        [key, value] => {
            let mut v = vec![];
            if value != "\"\"" {
                v = hex::decode(value).unwrap();
            }
            (key.to_owned(), v)
        }
        _ => unreachable!(),
    }
}
