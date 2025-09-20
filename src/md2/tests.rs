use super::*;

#[test]
fn test_md2() {
    let testcase = [
        ("", "8350e5a3e24c153df2275c9f80692773"),
        ("cc", "ae8444c84312bb77de47698c3e9209e5"),
        (
            "cd95aba1922f9ed8c30319b48826d564dd83049e2f62018a",
            "1fd50054c8f1d5d85c3e2650233da2a3",
        ),
        (
            "4645c73b3c341583742382d3",
            "4a359a8d58afd6ec93c45274ee8b3e1b",
        ),
    ];

    for (source, s) in testcase {
        let md2 = sum_md2(&hex::decode(source).unwrap());
        assert_eq!(
            &md2,
            hex::decode(s).unwrap().as_slice(),
            "{source} test failed."
        );
    }
}
