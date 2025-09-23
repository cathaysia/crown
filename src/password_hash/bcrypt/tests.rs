use super::*;

#[test]
fn test_bcrypting_is_easy() {
    let pass = b"mypassword";
    let hp = generate_from_password(pass, 0).expect("GenerateFromPassword error");

    assert!(
        compare_hash_and_password(&hp, pass).is_ok(),
        "{:?} should hash {:?} correctly",
        hp,
        pass
    );

    let not_pass = b"notthepass";
    let err = compare_hash_and_password(&hp, not_pass);
    assert!(
        matches!(err, Err(CryptoError::MismatchedHashAndPassword),),
        "{:?} and {:?} should be mismatched",
        hp,
        not_pass
    );
}

#[test]
fn test_bcrypting_is_correct() {
    let pass = b"allmine";
    let salt = b"XajjQvNhvvRt5GSeFk1xFe";
    let expected_hash = b"$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga";

    let hash = bcrypt(pass, 10, salt).expect("bcrypt blew up");
    assert!(
        expected_hash.ends_with(&hash),
        "{:?} should be the suffix of {:?}",
        hash,
        expected_hash
    );

    let h = new_from_hash(expected_hash).expect("Unable to parse hash");

    // This is not the safe way to compare these hashes. We do this only for
    // testing clarity. Use compare_hash_and_password()
    assert_eq!(
        expected_hash,
        h.to_hash().as_slice(),
        "Parsed hash {:?} should equal {:?}",
        h.to_hash(),
        expected_hash
    );
}

#[test]
fn test_very_short_passwords() {
    let key = b"k";
    let salt = b"XajjQvNhvvRt5GSeFk1xFe";
    let result = bcrypt(key, 10, salt);
    assert!(
        result.is_ok(),
        "One byte key resulted in error: {:?}",
        result
    );
}

#[test]
fn test_too_long_passwords_work() {
    let salt = b"XajjQvNhvvRt5GSeFk1xFe";
    // One byte over the usual 56 byte limit that blowfish has
    let too_long_pass = b"012345678901234567890123456789012345678901234567890123456";
    let too_long_expected = b"$2a$10$XajjQvNhvvRt5GSeFk1xFe5l47dONXg781AmZtd869sO8zfsHuw7C";
    let hash = bcrypt(too_long_pass, 10, salt).expect("bcrypt blew up on long password");
    assert!(
        too_long_expected.ends_with(&hash),
        "{:?} should be the suffix of {:?}",
        hash,
        too_long_expected
    );
}

struct InvalidHashTest {
    err: CryptoError,
    hash: &'static [u8],
}

const INVALID_TESTS: &[InvalidHashTest] = &[
    InvalidHashTest {
        err: CryptoError::HashTooShort,
        hash: b"$2a$10$fooo",
    },
    InvalidHashTest {
        err: CryptoError::HashTooShort,
        hash: b"$2a",
    },
    InvalidHashTest {
        err: CryptoError::HashVersionTooNew(b'3'),
        hash: b"$3a$10$sssssssssssssssssssssshhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
    },
    InvalidHashTest {
        err: CryptoError::InvalidHashPrefix(b'%'),
        hash: b"%2a$10$sssssssssssssssssssssshhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
    },
    InvalidHashTest {
        err: CryptoError::InvalidCost(32),
        hash: b"$2a$32$sssssssssssssssssssssshhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
    },
];

#[test]
fn test_invalid_hash_errors() {
    fn check(name: &str, expected: &CryptoError, err: Result<Hashed, CryptoError>) {
        match err {
            Ok(_) => panic!("{}: Should have returned an error", name),
            Err(actual_err) => {
                assert_eq!(
                    &actual_err, expected,
                    "{} gave err {:?} but should have given {:?}",
                    name, actual_err, expected
                );
            }
        }
    }

    for iht in INVALID_TESTS {
        let err = new_from_hash(iht.hash);
        check("new_from_hash", &iht.err, err);

        let ret = compare_hash_and_password(iht.hash, b"anything");
        assert_eq!(ret, Err(iht.err.clone()));
    }
}

#[test]
fn test_unpadded_base64_encoding() {
    let original = [
        101, 201, 101, 75, 19, 227, 199, 20, 239, 236, 133, 32, 30, 109, 243, 30,
    ];
    let encoded_original = b"XajjQvNhvvRt5GSeFk1xFe";

    let encoded = base64_encode(&original);

    assert_eq!(
        encoded_original,
        encoded.as_slice(),
        "Encoded {:?} should have equaled {:?}",
        encoded,
        encoded_original
    );

    let decoded = base64_decode(encoded_original).expect("base64_decode blew up");

    assert_eq!(
        decoded, original,
        "Decoded {:?} should have equaled {:?}",
        decoded, original
    );
}

#[test]
fn test_cost() {
    let suffix = "XajjQvNhvvRt5GSeFk1xFe5l47dONXg781AmZtd869sO8zfsHuw7C";
    let versions = ["2a", "2"];
    let costs = [4, 10];

    for vers in &versions {
        for &test_cost in &costs {
            let s = format!("${}${:02}${}", vers, test_cost, suffix);
            let h = s.as_bytes();
            let actual = cost(h).expect("Cost error");
            assert_eq!(
                actual, test_cost,
                "Cost, expected: {}, actual: {}",
                test_cost, actual
            );
        }
    }

    let malformed = format!("$a$a${}", suffix);
    let err = cost(malformed.as_bytes());
    assert!(err.is_err(), "Cost, malformed but no error returned");
}

#[test]
fn test_cost_validation_in_hash() {
    let pass = b"mypassword";

    for c in 0..MIN_COST {
        let p = new_from_password(pass, c).expect("new_from_password failed");
        assert_eq!(
            p.cost, DEFAULT_COST,
            "new_from_password should default costs below {} to {}, but was {}",
            MIN_COST, DEFAULT_COST, p.cost
        );
    }

    let p = new_from_password(pass, 14).expect("new_from_password failed");
    assert_eq!(
        p.cost, 14,
        "new_from_password should default cost to 14, but was {}",
        p.cost
    );

    let hp = new_from_hash(&p.to_hash()).expect("new_from_hash failed");
    assert_eq!(
        p.cost, hp.cost,
        "new_from_hash should maintain the cost at {}, but was {}",
        p.cost, hp.cost
    );

    let err = new_from_password(pass, 32);
    assert!(
        err.is_err(),
        "new_from_password: should return a cost error"
    );
    assert!(
        matches!(err.unwrap_err(), CryptoError::InvalidCost(32),),
        "new_from_password: should return cost error"
    );
}

#[test]
fn test_cost_returns_with_leading_zeroes() {
    let hp = new_from_password(b"abcdefgh", 7).expect("new_from_password failed");
    let hash = hp.to_hash();
    let cost = &hash[4..7];
    let expected = b"07$";

    assert_eq!(
        expected, cost,
        "single digit costs in hash should have leading zeros: was {:?} instead of {:?}",
        cost, expected
    );
}

#[test]
fn test_minor_not_required() {
    let no_minor_hash = b"$2$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga";
    let h = new_from_hash(no_minor_hash).expect("No minor hash blew up");
    assert_eq!(
        h.minor, 0,
        "Should leave minor version at 0, but was {}",
        h.minor
    );

    assert_eq!(
        no_minor_hash,
        h.to_hash().as_slice(),
        "Should generate hash {:?}, but created {:?}",
        no_minor_hash,
        h.to_hash()
    );
}
