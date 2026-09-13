#![cfg(feature = "radio")]

use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[test]
fn radio_he_mu_training_inventory() {
    let index = include_str!("fixtures/iq/he-mu-training-index.tsv");
    assert_eq!(index.lines().skip(1).count(), 384);
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "89d388695f4c197b44795849f67cae1cbd6c3a6a852fd99ff93481c404b5804f"
    );
    for row in index.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 9);
        let bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/iq")
                .join(format!("{}.cs8", c[0])),
        )
        .unwrap();
        assert_eq!(bytes.len(), 2 * c[7].parse::<usize>().unwrap());
        assert_eq!(hex(&Sha256::digest(&bytes)), c[8]);
    }
}

#[test]
fn radio_he_ldpc_partial_inventory() {
    let index = include_str!("fixtures/iq/he-ldpc-partial-index.tsv");
    assert_eq!(index.lines().skip(1).count(), 18);
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "de9e4120ff11daca41416a987b04e0236b3dfef5261c3462d76a06cd290a8425"
    );
    for row in index.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        let bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/iq")
                .join(format!("{}.cs8", c[0])),
        )
        .unwrap();
        assert_eq!(bytes.len() % 2, 0);
        assert_eq!(hex(&Sha256::digest(&bytes)), c[5]);
    }
}

#[test]
fn radio_he_er106_training_inventory() {
    let index = include_str!("fixtures/iq/he-er106-training-index.tsv");
    assert_eq!(index.lines().skip(1).count(), 54);
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "53b4eb9934866189c59a7fbb418ed447b979d8eccdaa5a13b2311221a67fbd66"
    );
    for row in index.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        let bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/iq")
                .join(format!("{}.cs8", c[0])),
        )
        .unwrap();
        assert_eq!(bytes.len(), 2 * c[6].parse::<usize>().unwrap());
        assert_eq!(hex(&Sha256::digest(&bytes)), c[7]);
    }
}

#[test]
fn radio_he_dcm_independent_inventory() {
    for (index, count, hash) in [
        (
            include_str!("fixtures/iq/he-dcm-metrics.tsv"),
            660,
            "c2033d5a6d75eb4aff85721511bf60fa2125038fd59a096a965be4ba99f873be",
        ),
        (
            include_str!("fixtures/iq/he-dcm-iq-index.tsv"),
            128,
            "fc4b672976f41c179d3cf8a388bb6d4e9844fd4c6f7141c2f41695a7d80e3e56",
        ),
        (
            include_str!("fixtures/iq/he-dcm-iq-invalid-index.tsv"),
            8,
            "fc26ea65326669bb2c605af7e37885d58e30360e4cf42e89ac851f0470f499f5",
        ),
    ] {
        assert_eq!(index.lines().skip(1).count(), count);
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), hash);
        if count == 660 {
            continue;
        }
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(bytes.len() % 2, 0);
            assert_eq!(hex(&Sha256::digest(&bytes)), *c.last().unwrap());
        }
    }
}

#[test]
fn radio_he_midamble_iq_independent_inventory() {
    for (index, count, hash) in [
        (
            include_str!("fixtures/iq/he-midamble-iq-index.tsv"),
            270,
            "5a4c886d78ab0221da3492c3d20eea3cb3fc4b159b999617c73966bbc7928b68",
        ),
        (
            include_str!("fixtures/iq/he-midamble-iq-invalid-index.tsv"),
            12,
            "712df6a3e8b59e6c9e5c1b4bd2f1e074d241121c490f1b83b509194c75b1b1b7",
        ),
    ] {
        assert_eq!(index.lines().skip(1).count(), count);
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), hash);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(bytes.len() % 2, 0);
            assert_eq!(hex(&Sha256::digest(&bytes)), *c.last().unwrap());
        }
    }
}

#[test]
fn radio_he_ldpc_iq_independent_inventory() {
    for (index, count, hash) in [
        (
            include_str!("fixtures/iq/he-ldpc-iq-index.tsv"),
            240,
            "91595117b54d5fa281949454db33da970a0de962c00032006ca4bac5cfbb54c0",
        ),
        (
            include_str!("fixtures/iq/he-ldpc-iq-invalid-index.tsv"),
            6,
            "4dc525ec58d1a8ced601edb9987988b9c75f3340358533dc985fcfb8458a75bb",
        ),
    ] {
        assert_eq!(index.lines().skip(1).count(), count);
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), hash);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(bytes.len() % 2, 0);
            assert_eq!(hex(&Sha256::digest(&bytes)), *c.last().unwrap());
        }
    }
}

#[test]
fn radio_he_demapping_independent_inventory() {
    for (index, count, digest) in [
        (
            include_str!("fixtures/iq/he-qam-index.tsv"),
            1313,
            "2f0e914ad4c1c9505cf2952d98fb0a1a308a9370eb27eb0ea27e789b838b2d7d",
        ),
        (
            include_str!("fixtures/iq/he-ldpc-tones.tsv"),
            234,
            "b64b4403383867d3d1aa9382baa4cf4a7d7e0536a35c381084c917b1a38d111f",
        ),
    ] {
        assert_eq!(index.lines().skip(1).count(), count);
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
    }
}

#[test]
fn radio_he_ldpc_rate_independent_inventory() {
    for (index, count, digest) in [
        (
            include_str!("fixtures/iq/he-er106-ldpc-rate-index.tsv"),
            705,
            "00044320324bb055031a989cd8f5b9f44df5a1321362a8e797c30e3dd6250301",
        ),
        (
            include_str!("fixtures/iq/he-er106-ldpc-rate-codewords.tsv"),
            57,
            "df509abf995e77c32bfde8a0a9553d972c5aa67a7be083b3c6f100547340076d",
        ),
        (
            include_str!("fixtures/iq/he-er242-ldpc-rate-index.tsv"),
            1839,
            "3cc66fe044aff08f68a479f60873e4adf18c9fe4199a3f5d67803334e1b76aea",
        ),
        (
            include_str!("fixtures/iq/he-er242-ldpc-rate-codewords.tsv"),
            159,
            "13150f2c9fafb59a916915a99b715828a8621214cc34ebb0e614b66bf7487258",
        ),
        (
            include_str!("fixtures/iq/he-ldpc-rate-index.tsv"),
            17583,
            "cd67b4b225fd05e1ffd694ecd9c7aabca00cedc34cf231fe57bbeacbf505221b",
        ),
        (
            include_str!("fixtures/iq/he-ldpc-rate-codewords.tsv"),
            72,
            "a666cf70157524543010190b6f30d0ceb97be2749782087113aad9e8bbf678f1",
        ),
    ] {
        assert_eq!(index.lines().skip(1).count(), count);
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
    }
}
#[test]
fn radio_he_ampdu_iq_independent_inventory() {
    let index = include_str!("fixtures/iq/he-ampdu-iq-index.tsv");
    assert_eq!(index.lines().skip(1).count(), 200);
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "026a46f976ab82f571e98d74fd26a1934a72491828951b7cfb1219e628998656"
    );
    for row in index.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        let bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/iq")
                .join(format!("{}.cs8", c[0])),
        )
        .unwrap();
        assert_eq!(bytes.len() % 2, 0);
        assert_eq!(hex(&Sha256::digest(&bytes)), c[9]);
    }
}

#[test]
fn radio_he_ampdu_independent_inventory() {
    let index = include_str!("fixtures/iq/he-ampdu-index.tsv");
    assert_eq!(index.lines().skip(1).count(), 46);
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "2967db32a13f23cb370a410ec457bb3781f7117cd21ef87bcd365b6261c2d30d"
    );
}

#[test]
fn radio_he_bcc_iq_independent_inventory() {
    for (index, count, digest, column) in [
        (
            include_str!("fixtures/iq/he-bcc-iq-index.tsv"),
            151,
            "cc482b26bee4c614f2b91222802d3b92fac3c7edf10d0142d9b154ff4be9eb18",
            12,
        ),
        (
            include_str!("fixtures/iq/he-bcc-iq-invalid-index.tsv"),
            6,
            "d8abb836c5f7cdc76f7e74b1ea7d92a189abb947c19b2ea7648d94234e32be20",
            2,
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
        assert_eq!(index.lines().skip(1).count(), count);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(hex(&Sha256::digest(&bytes)), c[column]);
            assert_eq!(bytes.len() % 2, 0);
            if column == 12 {
                assert!(bytes.len() / 2 >= c[11].parse::<usize>().unwrap());
            }
        }
    }
}

#[test]
fn radio_he_bcc_independent_inventory() {
    let index = include_str!("fixtures/iq/he-bcc-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "34be3a132c4d76b30cbdbd65082a379b9cb708adfdbb05b035b1197dab8635f4"
    );
    assert_eq!(index.lines().skip(1).count(), 435);
    for row in index.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 10);
        assert_eq!(c[7].len() % 2, 0);
        assert!(c[7].bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(c[8].bytes().all(|b| matches!(b, b'0' | b'1')));
    }
}

#[test]
fn radio_he_capacity_independent_inventory() {
    let index = include_str!("fixtures/iq/he-capacity-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "c5f05bab91ef075f49d3f05a5a71d16a9969e876f5e1c7c1e93243e6e0066642"
    );
    assert_eq!(index.lines().skip(1).count(), 8253);
    for row in index.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 19);
        assert!(c.iter().all(|v| v.parse::<usize>().is_ok()));
    }
}

#[test]
fn radio_he_timing_independent_inventory() {
    let index = include_str!("fixtures/iq/he-timing-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "22cbcb0dbf194548821bf1d9e86851f37e93baadc0e43766ed76576c8f63794a"
    );
    assert_eq!(index.lines().skip(1).count(), 10252);
    for row in index.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 16);
        assert!(c[..15].iter().all(|v| v.parse::<usize>().is_ok()));
        assert_eq!(c[15].len(), 64);
        assert!(c[15].bytes().all(|b| b.is_ascii_hexdigit()));
    }
}

#[test]
fn radio_he_er_timing_independent_inventory() {
    let index = include_str!("fixtures/iq/he-er-timing-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "9cc92600184627e1c6b8ac72b3b016a1c1d3458f7470a6935cda32b3cd811baa"
    );
    assert_eq!(index.lines().skip(1).count(), 2479);
    for row in index.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 16);
        assert!(c[..15].iter().all(|v| v.parse::<usize>().is_ok()));
        assert_eq!(c[15].len(), 64);
        assert!(c[15].bytes().all(|b| b.is_ascii_hexdigit()));
    }
}

#[test]
fn radio_he_er_capacity_independent_inventory() {
    for (index, count, digest) in [
        (
            include_str!("fixtures/iq/he-er106-capacity-index.tsv"),
            177,
            "fb3cae1a0cbce0c7da3e23a446f82b19ff0ea5ffdbf2c8bceae01e428e302231",
        ),
        (
            include_str!("fixtures/iq/he-er242-capacity-index.tsv"),
            619,
            "c14e68a1b1e2cfd1b4c380de74746bcfb37a2693a22993cf0482e8d51f6c4358",
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
        assert_eq!(index.lines().skip(1).count(), count);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            assert_eq!(c.len(), 19);
            assert!(c.iter().all(|v| v.parse::<usize>().is_ok()));
        }
    }
}

#[test]
fn radio_he_er_bcc_independent_inventory() {
    for (index, count, digest) in [
        (
            include_str!("fixtures/iq/he-er106-bcc-index.tsv"),
            165,
            "43bf9010944133740b9aa9c9260d055e1c19ae4e1f140b69396f9aa5969a1547",
        ),
        (
            include_str!("fixtures/iq/he-er242-bcc-index.tsv"),
            225,
            "aff08147ebfd2cd26e6dd5052f2a6d84c2285013a75aff4830673ff3ae75865f",
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
        assert_eq!(index.lines().skip(1).count(), count);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            assert_eq!(c.len(), 10);
            assert!(c[..7].iter().all(|v| v.parse::<usize>().is_ok()));
            assert_eq!(c[7].len() % 2, 0);
            assert!(c[7].bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(c[8].bytes().all(|b| b == b'0' || b == b'1'));
            assert!(matches!(c[9], "0" | "1"));
        }
    }
}

#[test]
fn radio_he_training4_independent_inventory() {
    for (index, count, digest, column) in [
        (
            include_str!("fixtures/iq/he-training-sparse-index.tsv"),
            36,
            "1c5741c605b8de45d5bb3f1eb0bc8c61acc6bad4b6fd3f5938dcf7dfe9c94595",
            13,
        ),
        (
            include_str!("fixtures/iq/he-training4-index.tsv"),
            24,
            "17fee2b42df2d6c47b42ed75dbb9728889e0b5396dff24406cebaaf1df295beb",
            13,
        ),
        (
            include_str!("fixtures/iq/he-training4-invalid-index.tsv"),
            5,
            "13a7066808a4a502e5f2005b6cb111d280590622cb39e4061eabf4e128107631",
            2,
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
        assert_eq!(index.lines().skip(1).count(), count);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(hex(&Sha256::digest(&bytes)), c[column]);
            assert_eq!(bytes.len() % 2, 0);
            if column == 13 {
                assert_eq!(bytes.len() / 2, c[12].parse::<usize>().unwrap());
                assert_eq!(c[9].len(), 242);
            }
        }
    }
}

#[test]
fn radio_he_er_prefix_independent_inventory() {
    for (index, count, digest) in [
        (
            include_str!("fixtures/iq/he-er-prefix-index.tsv"),
            288,
            "55590eb00e6989408b5cdf26114004a7ab57e588e7872dea33d59c864cddebd8",
        ),
        (
            include_str!("fixtures/iq/he-er-prefix-invalid-index.tsv"),
            18,
            "a52d69814d68e8f805efd7efd6d44eb3e3c00eca65c2565ffc40e938d3fe4f66",
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
        assert_eq!(index.lines().skip(1).count(), count);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(hex(&Sha256::digest(&bytes)), *c.last().unwrap());
            assert_eq!(bytes.len() % 2, 0);
            if count == 288 {
                assert_eq!(c.len(), 6);
                assert_eq!(c[1].len(), 52);
                assert_eq!(c[2].len(), 208);
                assert_eq!(bytes.len() / 2, c[4].parse::<usize>().unwrap());
            }
        }
    }
}

#[test]
fn radio_he_stbc_independent_inventory() {
    for (index, count, digest) in [
        (
            include_str!("fixtures/iq/he-stbc-iq-index.tsv"),
            368,
            "6a450e01748022ca63e1aa30836c81d74d731ea28bdffa30e84eae119abef1d9",
        ),
        (
            include_str!("fixtures/iq/he-stbc-iq-invalid-index.tsv"),
            8,
            "3f865fb4a1a91c8b9c0ed3e99398460143730727da82d7e74b1ee26f507dbbc6",
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
        assert_eq!(index.lines().skip(1).count(), count);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(hex(&Sha256::digest(&bytes)), *c.last().unwrap());
            assert_eq!(bytes.len() % 2, 0);
            if count == 368 {
                assert_eq!(c.len(), 12);
                assert!(c[9].parse::<usize>().unwrap() < c[10].parse::<usize>().unwrap());
                assert!(c[10].parse::<usize>().unwrap() <= bytes.len() / 2);
            }
        }
    }
}

#[test]
fn radio_he_er_iq_independent_inventory() {
    for (index, count, digest) in [
        (
            include_str!("fixtures/iq/he-er106-iq-index.tsv"),
            104,
            "01ee9000428eddb43d7a3e53aecc8ab8e880ac496a055ff7bfd44ae59806aa7a",
        ),
        (
            include_str!("fixtures/iq/he-er106-iq-invalid-index.tsv"),
            16,
            "de14caf79bcc26c530515c7b6138dde298d724c2e39a9f2a1a75546cad41f8a9",
        ),
        (
            include_str!("fixtures/iq/he-er-iq-index.tsv"),
            280,
            "2f8d73cbc26f8fbd3008c437d49a830da27102ab411cc108ef90556be001de07",
        ),
        (
            include_str!("fixtures/iq/he-er-iq-invalid-index.tsv"),
            16,
            "40361f35eb6fde27f06a6551ede214bca579a1c9019167385731bef87a8d4c4d",
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
        assert_eq!(index.lines().skip(1).count(), count);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(hex(&Sha256::digest(&bytes)), *c.last().unwrap());
            assert_eq!(bytes.len() % 2, 0);
            if count == 280 || count == 104 {
                assert_eq!(c.len(), 14);
                assert!(c[9].parse::<usize>().unwrap() < c[10].parse::<usize>().unwrap());
                assert!(c[10].parse::<usize>().unwrap() <= bytes.len() / 2);
            }
        }
    }
}

#[test]
fn radio_he_transform_independent_inventory() {
    let index = include_str!("fixtures/iq/he-transform-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "4c2f58473a40a86af3e90fbfaf56ad71ba0a5d6f1ad2d50824c91c82cb52c312"
    );
    assert_eq!(index.lines().skip(1).count(), 1920);
    for row in index.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 7);
        assert!(matches!(c[1], "128" | "256"));
        assert!(c[2].parse::<usize>().unwrap() < c[1].parse::<usize>().unwrap());
        assert!(c[3..].iter().all(|s| s.parse::<f64>().unwrap().is_finite()));
    }
}

#[test]
fn radio_he_su_prefix_independent_inventory() {
    for (index, count, digest, column) in [
        (
            include_str!("fixtures/iq/he-su-prefix-index.tsv"),
            96,
            "44e3444fee65a4b73e6ad033813221360838c996ab691df664e5d0f4580a34bc",
            4,
        ),
        (
            include_str!("fixtures/iq/he-su-prefix-invalid-index.tsv"),
            10,
            "50525a89cdd9af70d1cc80e7ed923f68bf3bb0b75b45c877d1f648fc2d287fb4",
            2,
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
        assert_eq!(index.lines().skip(1).count(), count);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(bytes.len(), 1354);
            assert_eq!(hex(&Sha256::digest(&bytes)), c[column]);
        }
    }
}

#[test]
fn radio_he_sig_b_users_inventory() {
    use crafter::prelude::{
        HeSigBUserBlock, HeSigBUserContext, HeSigBUserEncoding, HeSigBUserFields,
    };
    let rows = include_str!("fixtures/iq/he-sig-b-users.tsv");
    assert_eq!(rows.lines().skip(1).count(), 3175);
    assert_eq!(
        hex(&Sha256::digest(rows.as_bytes())),
        "bfc0c7ff5fec8b4c0eca0fc694c6d60a59502115e9ebd53ede47888fd4fd5d00"
    );
    for row in rows.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 3);
        assert!(matches!(c[0].len(), 31 | 52));
        assert!(c[0].bytes().all(|b| matches!(b, b'0' | b'1')));
    }
    let c: Vec<_> = rows.lines().nth(1).unwrap().split('\t').collect();
    let bits: Vec<_> = c[0].bytes().map(|b| b - b'0').collect();
    let block = HeSigBUserBlock::decode(
        &bits,
        &[HeSigBUserContext::MuMimo {
            users: 2,
            position: 0,
        }],
    )
    .unwrap();
    assert!(matches!(
        block.users(),
        [Ok(HeSigBUserFields {
            sta_id: 123,
            encoding: HeSigBUserEncoding::MuMimo {
                streams: 1,
                start_stream: 0,
                total_streams: 2,
                ..
            }
        })]
    ));
}

#[test]
fn radio_he_sig_b_coded_inventory() {
    let rows = include_str!("fixtures/iq/he-sig-b-coded.tsv");
    assert_eq!(rows.lines().skip(1).count(), 450);
    assert_eq!(
        hex(&Sha256::digest(rows.as_bytes())),
        "52ca8c6824a55ceeaa182bf24b6d8b4f73c02fc57c9893fd1d7520f29163b035"
    );
    for row in rows.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 7);
        assert!(c[0].parse::<u8>().unwrap() <= 5);
        for bits in c[4].split(';') {
            assert!(matches!(bits.len(), 18 | 31 | 52));
            assert!(bits.bytes().all(|b| matches!(b, b'0' | b'1')));
        }
        assert!(c[5].bytes().all(|b| matches!(b, b'0' | b'1')));
        assert!(c[6].parse::<usize>().unwrap() < c[5].len());
    }
}

#[test]
fn radio_he_sig_b_modulation_inventory() {
    let rows = include_str!("fixtures/iq/he-sig-b-modulation.tsv");
    assert_eq!(rows.lines().skip(1).count(), 1564);
    assert_eq!(
        hex(&Sha256::digest(rows.as_bytes())),
        "3b5116f8eb04070b86b39eb2dd0b7bcb31b4254f471f85dce66a246b4c0163c0"
    );
    let mut symbols = 0;
    for row in rows.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 9);
        let mcs: usize = c[0].parse().unwrap();
        let dcm: usize = c[1].parse().unwrap();
        assert!(mcs <= 5 && dcm <= 1 && (dcm == 0 || [0, 1, 3, 4].contains(&mcs)));
        let per_symbol = 52 * [1, 2, 2, 4, 4, 6][mcs] / (1 + dcm);
        assert_eq!(c[7].len() % per_symbol, 0);
        assert!(c[7].bytes().all(|b| matches!(b, b'0' | b'1')));
        assert_eq!(c[8].split(';').count(), 52 * c[7].len() / per_symbol);
        if c[6] == "-" {
            symbols += 1;
            assert_eq!(c[7].len(), per_symbol);
        }
    }
    assert_eq!(symbols, 1294);
}

#[test]
fn radio_he_sig_b_iq_inventory() {
    let rows = include_str!("fixtures/iq/he-sigb-iq-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 172);
    assert_eq!(
        hex(&Sha256::digest(rows.as_bytes())),
        "c132bfe018dae64eb29d81df1f7463d6432f1507ddb0a2a6c01b41a784745d9e"
    );
    for row in rows.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 8);
        let bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/iq")
                .join(format!("{}.cs8", c[0])),
        )
        .unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[7]);
        assert_eq!(bytes.len(), 2 * c[6].parse::<usize>().unwrap());
        let symbols = c[4].parse::<usize>().unwrap();
        assert!((1..=36).contains(&symbols));
        assert_eq!(bytes.len() / 2, 677 + 80 * symbols);
    }
}

#[test]
fn radio_he_mu_timing_inventory() {
    let rows = include_str!("fixtures/iq/he-mu-timing.tsv");
    assert_eq!(rows.lines().skip(1).count(), 26529);
    assert_eq!(
        hex(&Sha256::digest(rows.as_bytes())),
        "2dfa1adafa5ea32f957aa72d74f51e0746a6ad8987f55849a10ab6d5fa9e85f9"
    );
    for row in rows.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 16);
        let n: Vec<usize> = c[..15].iter().map(|s| s.parse().unwrap()).collect();
        assert!((1..=36).contains(&n[5]));
        assert_eq!(n[8] % 3, 2);
        assert!(n[8] <= 4095);
        assert!(n[11] < n[12] && n[12] <= n[13] && n[13] <= n[14]);
        assert_eq!(c[15].len(), 64);
    }
}

#[test]
fn radio_he_sig_b_common_inventory() {
    use crafter::prelude::{HeSigBCommon20Fields, HeSigBError};
    let rows = include_str!("fixtures/iq/he-sig-b-common.tsv");
    assert_eq!(rows.lines().skip(1).count(), 256);
    assert_eq!(
        hex(&Sha256::digest(rows.as_bytes())),
        "763265fe78ae7fe9a0bff9c93972e856931d1aa5eaae9c9ae0efc205f8e34051"
    );
    for row in rows.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 5);
        assert_eq!(c[1].len(), 18);
        assert!(c[1].bytes().all(|b| matches!(b, b'0' | b'1')));
        let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
        match HeSigBCommon20Fields::decode(&bits) {
            Ok(fields) => {
                assert_eq!(c[2], "ok");
                assert_eq!(fields.user_count(), c[4].parse::<u8>().unwrap());
            }
            Err(HeSigBError::ReservedAllocation(_)) => assert_eq!(c[2], "reserved"),
            Err(HeSigBError::WiderAllocation(_)) => assert_eq!(c[2], "wider"),
            other => panic!("unexpected result: {other:?}"),
        }
    }
}

#[test]
fn radio_he_mu_prefix_inventory() {
    for (index, count, digest) in [
        (
            include_str!("fixtures/iq/he-mu-prefix-index.tsv"),
            160,
            "7163b9ba255cfd4993d38a880b3bbd0c605c7d73198ae80fed2fbafc34a9a123",
        ),
        (
            include_str!("fixtures/iq/he-mu-prefix-invalid-index.tsv"),
            13,
            "0a501489eff638f0c4d84086e72da628a97d92b01bcc2c5c20028f9800d27997",
        ),
    ] {
        assert_eq!(index.lines().skip(1).count(), count);
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(bytes.len(), 1354);
            assert_eq!(hex(&Sha256::digest(&bytes)), *c.last().unwrap());
        }
    }
}

#[test]
fn radio_he_mu_signal_a_independent_inventory() {
    for (index, count, digest, columns) in [
        (
            include_str!("fixtures/iq/he-mu-signal-a-index.tsv"),
            5280,
            "6fd4084a1c8696980295f61999734e7ab05a9efdebf6fe72818bee043ba57a8a",
            19,
        ),
        (
            include_str!("fixtures/iq/he-mu-signal-a-invalid.tsv"),
            24,
            "c15bc730a40429bbe66af2a60ca084c39c762534ae97ea962e147d31bb785181",
            4,
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(index.as_bytes())), digest);
        assert_eq!(index.lines().skip(1).count(), count);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            assert_eq!(c.len(), columns);
            let bits = c[usize::from(columns == 4)];
            assert_eq!(bits.len(), 52);
            assert!(bits.bytes().all(|b| matches!(b, b'0' | b'1')));
            if columns == 19 {
                assert_eq!(c[1].len(), 104);
                assert!(c[1].bytes().all(|b| matches!(b, b'0' | b'1')));
                let bits: Vec<_> = bits.bytes().map(|b| b - b'0').collect();
                let fields = crafter::prelude::HeMuSignalFields::decode(&bits).unwrap();
                assert_eq!(fields.sig_b_symbols_or_users, c[8].parse::<u8>().unwrap());
            }
        }
    }
}

#[test]
fn radio_he_signal_a_independent_inventory() {
    let index = include_str!("fixtures/iq/he-signal-a-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "8dac04fd1271ebc67acf7f237029dbb4abaa00da9ca531fdd069caae68f3f4e7"
    );
    assert_eq!(index.lines().skip(1).count(), 1984);
    for row in index.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 20);
        assert_eq!(c[0].len(), 52);
        assert_eq!(c[1].len(), 104);
        assert!(c[..2]
            .iter()
            .all(|s| s.bytes().all(|b| matches!(b, b'0' | b'1'))));
    }
}

#[test]
fn radio_vht_stbc_iq_independent_inventory() {
    let index = include_str!("fixtures/iq/vht-stbc-iq-index.tsv");
    let invalid = include_str!("fixtures/iq/vht-stbc-iq-invalid-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "d475eeb97bab4cbf0bd773ce40c6efe638dad84baddd473392e5523d27958dd8"
    );
    assert_eq!(
        hex(&Sha256::digest(invalid.as_bytes())),
        "291f1204bea7af0b7f5f3a9bd2a2e8849d49b0ad58afa64dfe46b015ba3c7bc2"
    );
    assert_eq!(index.lines().skip(1).count(), 110);
    assert_eq!(invalid.lines().skip(1).count(), 9);
    let mut names = std::collections::BTreeSet::new();
    for (rows, column) in [(index, 6), (invalid, 2)] {
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            assert!(names.insert(c[0]));
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(hex(&Sha256::digest(&bytes)), c[column]);
            assert_eq!(bytes.len() % 2, 0);
        }
    }
}

#[test]
fn radio_vht_ldpc_iq_independent_inventory() {
    let index = include_str!("fixtures/iq/vht-ldpc-iq-index.tsv");
    let invalid = include_str!("fixtures/iq/vht-ldpc-iq-invalid-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(index.as_bytes())),
        "a027fff896f1a7cb96767e47d417aff5fe8b3484ff4aeab6917531f1c73aa693"
    );
    assert_eq!(
        hex(&Sha256::digest(invalid.as_bytes())),
        "9edb13a9c24d5ce8ec5413f567786e9f1484e3641d6f1e18c38cfe6eadfbacd3"
    );
    assert_eq!(index.lines().skip(1).count(), 73);
    assert_eq!(invalid.lines().skip(1).count(), 3);
    let mut names = std::collections::BTreeSet::new();
    for (rows, column) in [(index, 6), (invalid, 2)] {
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            assert!(names.insert(c[0]));
            let bytes = fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            assert_eq!(hex(&Sha256::digest(&bytes)), c[column]);
            assert_eq!(bytes.len() % 2, 0);
        }
    }
}

#[test]
fn radio_vht_ldpc_rate_independent_inventory() {
    for (data, count, digest, columns) in [
        (
            include_str!("fixtures/iq/vht-ldpc-rate-index.tsv"),
            20412,
            "a1ea0c327c1293a5ba88a6d823744b8170906ae944da2afbdec666b5ce3e49ec",
            11,
        ),
        (
            include_str!("fixtures/iq/vht-ldpc-rate-codewords.tsv"),
            54,
            "8c63b75d5e434a4807411b9299be4e586ebe4722aeb409ee51f5d2eec3f81bc3",
            5,
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(data.as_bytes())), digest);
        assert_eq!(data.lines().skip(1).count(), count);
        let mut keys = std::collections::BTreeSet::new();
        for row in data.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            assert_eq!(c.len(), columns);
            assert!(keys.insert((c[0], c[1], c[2])));
        }
    }
}

#[test]
fn radio_vht_reference_independent_inventory() {
    let inventory = include_str!("fixtures/iq/vht-reference-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(inventory.as_bytes())),
        "6d04d84d617e203eb9690468bd89690f91f6c378f208d3a204201ae9f190ceed"
    );
    assert_eq!(inventory.lines().skip(1).count(), 9253);
    let mut names = std::collections::BTreeSet::new();
    for row in inventory.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 4);
        assert!(names.insert(c[0]));
        assert_eq!(c[1].len(), 24);
        assert!(c[2].is_empty() || c[2].len() == 16);
    }
}

#[test]
fn radio_vht_ampdu_iq_independent_inventory() {
    let inventory = include_str!("fixtures/iq/vht-ampdu-iq-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(inventory.as_bytes())),
        "f5ccd1144fc3fb1e02aa71a1953b99cac93ad087b9ad800b7a6d420e60ba7518"
    );
    assert_eq!(inventory.lines().skip(1).count(), 54);
    let mut modes = std::collections::BTreeSet::new();
    for row in inventory.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 9);
        let bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/iq")
                .join(format!("{}.cs8", c[0])),
        )
        .unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[6]);
        assert!(bytes.len() >= 2 * (c[7].parse::<usize>().unwrap() + 64));
        let shape = if c[0].ends_with("large") {
            "large"
        } else if c[0].ends_with("bad-fcs") {
            "bad-fcs"
        } else {
            "duplicate"
        };
        modes.insert((
            c[1].parse::<u8>().unwrap(),
            c[2].parse::<u8>().unwrap(),
            shape,
        ));
    }
    for mcs in 0..9 {
        for gi in [8, 16] {
            for shape in ["large", "bad-fcs", "duplicate"] {
                assert!(modes.contains(&(mcs, gi, shape)));
            }
        }
    }
}

#[test]
fn radio_vht_ampdu_independent_inventory() {
    for (inventory, digest, count, columns) in [
        (
            include_str!("fixtures/iq/vht-ampdu-delimiters.tsv"),
            "25d3b8e2cee53ebd56e68b2d0b199e90b9143df0410c7b540ae75f94345321dc",
            16384,
            3,
        ),
        (
            include_str!("fixtures/iq/vht-ampdu-index.tsv"),
            "bd4da6dce66701f14c88a4e6acc19f34a4508663e716c3ba95600941260a7c61",
            144,
            5,
        ),
    ] {
        assert_eq!(hex(&Sha256::digest(inventory.as_bytes())), digest);
        assert_eq!(inventory.lines().skip(1).count(), count);
        let mut names = std::collections::BTreeSet::new();
        for row in inventory.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            assert_eq!(c.len(), columns);
            assert!(names.insert(c[0]));
        }
    }
}

#[test]
fn radio_vht_bcc_iq_independent_inventory() {
    use crafter::{VhtSignalAFields, VhtSignalAUsers, VhtSignalB20Fields};
    let inventory = include_str!("fixtures/iq/vht-bcc-iq-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(inventory.as_bytes())),
        "02ad3e1dea0141b105f245af706ae9f3550b9c2b51aab62a97b0120bb5e47527"
    );
    assert_eq!(inventory.lines().skip(1).count(), 108);
    let invalid = include_str!("fixtures/iq/vht-bcc-iq-invalid-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(invalid.as_bytes())),
        "657c80df10ede9280dc033317a97c306b7c564ae61a6f888f60b72a4b9d8c142"
    );
    assert_eq!(invalid.lines().skip(1).count(), 8);
    for row in invalid.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 3);
        let bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/iq")
                .join(format!("{}.cs8", c[0])),
        )
        .unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[2]);
    }
    let mut names = std::collections::BTreeSet::new();
    let mut modes = std::collections::BTreeSet::new();
    for row in inventory.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 14);
        assert!(names.insert(c[0]));
        let mcs = c[1].parse::<u8>().unwrap();
        let guard = c[2].parse::<usize>().unwrap();
        let symbols = c[3].parse::<usize>().unwrap();
        let start = c[10].parse::<usize>().unwrap();
        let end = c[11].parse::<usize>().unwrap();
        let signaled_end = c[12].parse::<usize>().unwrap();
        let bits = |s: &str| s.bytes().map(|b| b - b'0').collect::<Vec<_>>();
        let a = VhtSignalAFields::decode(&bits(c[5])).unwrap();
        let b = VhtSignalB20Fields::decode(&bits(c[6]), false).unwrap();
        assert!(
            matches!(a.users, VhtSignalAUsers::Single { mcs: n, space_time_streams: 1, ldpc: false, .. } if n == mcs)
        );
        assert_eq!(a.short_guard_interval, guard == 8);
        assert_eq!(a.short_gi_disambiguation, guard == 8 && symbols % 10 == 9);
        assert_eq!(start, 837);
        assert_eq!(end, start + (64 + guard) * symbols);
        assert!(signaled_end >= end && signaled_end - end < 80);
        let apep = c[13].parse::<u32>().unwrap();
        let (low, high) = b.apep_length_bounds().unwrap();
        assert!(low <= apep && apep <= high);
        let bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/iq")
                .join(format!("{}.cs8", c[0])),
        )
        .unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[9]);
        assert_eq!(bytes.len(), 2 * (signaled_end + 64));
        modes.insert((
            mcs,
            guard,
            a.short_gi_disambiguation,
            c[0].ends_with("offset"),
        ));
    }
    for mcs in 0..9 {
        for offset in [false, true] {
            assert!(modes.contains(&(mcs, 16, false, offset)));
            for disambiguation in [false, true] {
                assert!(modes.contains(&(mcs, 8, disambiguation, offset)));
            }
        }
    }
}

#[test]
fn radio_vht_bcc_data_independent_inventory() {
    let inventory = include_str!("fixtures/iq/vht-bcc-data-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(inventory.as_bytes())),
        "b3f3ebe56b10f6269180fa8704b50939c49e2868ba00b023fe259f68a8f141a3"
    );
    let mut seeds = std::collections::BTreeSet::new();
    let mut dimensions = std::collections::BTreeSet::new();
    let mut valid = 0;
    let mut invalid = 0;
    for row in inventory.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 7);
        assert_eq!(c[3].len(), 26);
        assert!(c[3]
            .bytes()
            .chain(c[5].bytes())
            .all(|b| b == b'0' || b == b'1'));
        if c[6] == "1" {
            valid += 1;
            seeds.insert(c[2].parse::<u8>().unwrap());
            dimensions.insert((c[0].parse::<u8>().unwrap(), c[1].parse::<u16>().unwrap()));
        } else {
            assert_eq!(c[6], "0");
            invalid += 1;
        }
    }
    assert_eq!((valid, invalid), (289, 27));
    assert_eq!(seeds, (1..=127).collect());
    for dimension in [(0, 1512), (8, 40), (8, 1512)] {
        assert!(dimensions.contains(&dimension));
    }
    for mcs in 0..9 {
        for symbols in [2, 3, 4, 5, 10, 17] {
            assert!(dimensions.contains(&(mcs, symbols)));
        }
    }
}

#[test]
fn radio_vht_qam_independent_inventory() {
    let inventory = include_str!("fixtures/iq/vht-qam-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(inventory.as_bytes())),
        "93f7dbd354872a0b18274a99e11b7d27bd6b19748f9b8b820a8a8ad95e05af73"
    );
    let mut labels = std::collections::BTreeSet::new();
    let mut off_grid = 0;
    for row in inventory.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 11);
        if c[2] == "-" {
            off_grid += 1;
        } else {
            assert_eq!(c[2].len(), 8);
            assert!(c[2].bytes().all(|b| b == b'0' || b == b'1'));
            assert!(labels.insert(c[2]));
        }
        for index in [0, 1, 3, 4, 5, 6, 7, 8, 9, 10] {
            assert!(c[index].parse::<f64>().unwrap().is_finite());
        }
    }
    assert_eq!(labels.len(), 256);
    assert_eq!(off_grid, 145);
}

#[test]
fn radio_vht_timing_independent_inventory() {
    let inventory = include_str!("fixtures/iq/vht-timing-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(inventory.as_bytes())),
        "846aab93b8bbbee30b966aa535d3117ed234759089e3cc264e8bc69e7a1dc70a"
    );
    assert_eq!(inventory.lines().skip(1).count(), 1105);
    let mut dimensions = std::collections::BTreeSet::new();
    for row in inventory.lines().skip(1) {
        let c: Vec<usize> = row.split('\t').map(|s| s.parse().unwrap()).collect();
        assert_eq!(c.len(), 10);
        dimensions.insert((c[0], c[1], c[2]));
    }
    for streams in 1..=8 {
        for short in 0..=1 {
            assert!(dimensions.contains(&(streams, short, 0)));
            assert_eq!(dimensions.contains(&(streams, short, 1)), streams % 2 == 0);
        }
    }
}

#[test]
fn radio_vht_sig_b_public_paths_and_inventory() {
    use crafter::prelude::{VhtSignalB20Content, VhtSignalB20Error, VhtSignalB20Fields};
    let inventory = include_str!("fixtures/iq/vht-signal-b20-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(inventory.as_bytes())),
        "62957edc7e0b8b7de05472e07e6078565ef830d8de1c15fed772ce8ff981afe3"
    );
    assert_eq!(inventory.lines().skip(1).count(), 225);
    let mut ndps = 0;
    let mut headers = std::collections::BTreeSet::new();
    for row in inventory.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 9);
        assert!(headers.insert((c[0], c[1])));
        let input: Vec<_> = c[0].bytes().map(|b| b - b'0').collect();
        let result: Result<crafter::radio::VhtSignalB20Fields, crafter::VhtSignalB20Error> =
            VhtSignalB20Fields::decode(&input, c[1] == "1");
        let f = result.unwrap();
        if f.content() == VhtSignalB20Content::Ndp {
            ndps += 1;
            assert_eq!(c[1], "0");
            assert_eq!(
                f.verify_service(&[]),
                Err(VhtSignalB20Error::NoServiceForNdp)
            );
        } else {
            let service: Vec<_> = c[7].bytes().map(|b| b - b'0').collect();
            f.verify_service(&service).unwrap();
            assert_eq!(
                f.apep_length_bounds(),
                Some((c[5].parse().unwrap(), c[6].parse().unwrap()))
            );
        }
    }
    assert_eq!(ndps, 1);
}

#[test]
fn radio_vht_signal_a_public_paths() {
    use crafter::prelude::{VhtSignalAError, VhtSignalAFields, VhtSignalAUsers};
    let input: Vec<_> = include_str!("fixtures/iq/vht-signal-a-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .next()
        .unwrap()
        .bytes()
        .map(|b| b - b'0')
        .collect();
    let result: Result<crafter::radio::VhtSignalAFields, crafter::VhtSignalAError> =
        VhtSignalAFields::decode(&input);
    assert!(matches!(
        result.unwrap().users,
        VhtSignalAUsers::Single { .. }
    ));
    assert_eq!(
        VhtSignalAFields::decode(&[]),
        Err(VhtSignalAError::BitCount {
            required: 48,
            available: 0
        })
    );
}

#[test]
fn radio_vht_signal_a_independent_inventory() {
    let inventory = include_str!("fixtures/iq/vht-signal-a-index.tsv");
    assert_eq!(
        hex(&Sha256::digest(inventory.as_bytes())),
        "653021668de364d2ce3c7716968d0e32a54eb297df0c67ead63b0f96e5e2d81f"
    );
    let mut headers = std::collections::BTreeSet::new();
    let mut groups = std::collections::BTreeSet::new();
    let mut single_user = 0;
    let mut multi_user = 0;
    for row in inventory.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 13);
        assert_eq!(c[0].len(), 48);
        assert_eq!(c[12].len(), 96);
        assert!(c[0]
            .bytes()
            .chain(c[12].bytes())
            .all(|b| b == b'0' || b == b'1'));
        assert!(headers.insert(c[0]));
        let number = |i: usize| c[i].parse::<usize>().unwrap();
        let group = number(2);
        let width = number(1);
        assert!(width <= 3 && group <= 63);
        groups.insert((group, width));
        for i in [3, 5, 6, 7, 8, 9, 11] {
            assert!(number(i) <= 1);
        }
        assert!(number(6) <= number(5));
        assert_eq!(&c[0][42..], "000000");
        if group == 0 || group == 63 {
            single_user += 1;
            assert!(number(10) <= 9);
            let nsts = (number(4) & 7) + 1;
            assert!(number(3) == 0 || nsts % 2 == 0);
        } else {
            multi_user += 1;
            assert_eq!(number(3), 0);
            assert_eq!(number(11), 1);
            assert_ne!(number(10) & 8, 0);
            for user in 0..4 {
                let nsts = (number(4) >> (3 * user)) & 7;
                assert!(nsts <= 4);
                if nsts == 0 {
                    let coding = if user == 0 {
                        number(9)
                    } else {
                        (number(10) >> (user - 1)) & 1
                    };
                    assert_eq!(coding, 1);
                }
            }
        }
    }
    assert_eq!((single_user, multi_user), (640, 1240));
    assert_eq!(headers.len(), 1880);
    assert_eq!(groups.len(), 64 * 4);
}

#[test]
fn radio_extension_training_independent_waveform_integrity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let rows: Vec<_> = include_str!("fixtures/iq/ht-extension-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(rows.len(), 540);
    let mut matrix = std::collections::BTreeSet::new();
    for row in rows {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 13);
        let number = |i: usize| c[i].parse::<usize>().unwrap();
        let bytes = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[5]);
        assert_eq!(bytes.len(), 2 * number(6));
        assert!(number(1) < 8 && number(9) < 2 && number(10) < 2 && number(11) < 2);
        assert!((1..=3).contains(&number(12)));
        assert!(1 + number(11) + number(12) <= 4);
        let extra = [0, 1, 2, 4][number(12)];
        assert!(1 + number(11) + extra <= 5);
        if number(10) == 1 {
            assert_eq!(number(2), 16);
        }
        if number(11) == 1 {
            assert_eq!(number(3) % 2, 0);
        }
        assert!([8, 16].contains(&number(2)));
        assert_eq!(
            number(7),
            37 + (if number(10) == 1 { 480 } else { 720 }) + 80 * (number(11) + extra)
        );
        assert_eq!(number(8), number(7) + (64 + number(2)) * number(3));
        assert_eq!(number(6), number(8) + 64);
        let psdu: Vec<_> = (0..c[4].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&c[4][i..i + 2], 16).unwrap())
            .collect();
        let end = psdu.len() - 4;
        assert_eq!(
            crc(&psdu[..end]),
            u32::from_le_bytes(psdu[end..].try_into().unwrap())
        );
        assert!([100, 4095].contains(&psdu.len()));
        if psdu.len() == 4095 {
            assert!([0, 7].contains(&number(1)) && c[0].ends_with("offset"));
        }
        assert!(matrix.insert((
            number(1),
            number(2),
            number(9),
            number(10),
            number(11),
            number(12),
            psdu.len(),
            c[0].ends_with("offset")
        )));
    }
    assert_eq!(matrix.len(), 540);
    let aggregates: Vec<_> = include_str!("fixtures/iq/ht-extension-ampdu-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(aggregates.len(), 62);
    for row in aggregates {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 12);
        let bytes = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[7]);
        assert_eq!(bytes.len() / 2, c[8].parse::<usize>().unwrap() + 64);
    }
}

#[test]
fn radio_stbc_independent_waveform_integrity() {
    // Inventory integrity is distinct from receiver support.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let rows: Vec<_> = include_str!("fixtures/iq/ht-stbc-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(rows.len(), 192);
    let mut matrix = std::collections::BTreeSet::new();
    for row in rows {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 11);
        let number = |i: usize| c[i].parse::<usize>().unwrap();
        let bytes = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[5]);
        assert_eq!(bytes.len(), 2 * number(6));
        assert_eq!(number(3) % 2, 0);
        assert!([8, 16].contains(&number(2)));
        assert!(number(1) < 8 && number(9) < 2 && number(10) < 2);
        let greenfield = number(10) == 1;
        if greenfield {
            assert_eq!(number(2), 16);
        }
        assert_eq!(number(7), 37 + if greenfield { 560 } else { 800 });
        assert_eq!(number(8), number(7) + (64 + number(2)) * number(3));
        assert_eq!(number(6), number(8) + 64);
        let psdu: Vec<_> = (0..c[4].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&c[4][i..i + 2], 16).unwrap())
            .collect();
        let end = psdu.len() - 4;
        assert_eq!(
            crc(&psdu[..end]),
            u32::from_le_bytes(psdu[end..].try_into().unwrap())
        );
        assert!([100, 4095].contains(&psdu.len()));
        assert!(matrix.insert((
            number(1),
            number(2),
            number(9),
            greenfield,
            psdu.len(),
            c[0].ends_with("offset")
        )));
    }
    let invalid: Vec<_> = include_str!("fixtures/iq/ht-stbc-invalid-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(invalid.len(), 9);
    let mut faults = std::collections::BTreeSet::new();
    for row in invalid {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 4);
        let bytes = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(hex(&Sha256::digest(&bytes)), c[2]);
        assert_eq!(bytes.len(), 2 * c[3].parse::<usize>().unwrap());
        assert!(faults.insert(c[1]));
    }
}

#[test]
fn radio_greenfield_independent_fixture_integrity() {
    // This checks oracle artifacts, not receive support or interoperability.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let rows: Vec<_> = include_str!("fixtures/iq/ht-greenfield-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(rows.len(), 64);
    let mut matrix = std::collections::BTreeSet::new();
    for row in rows {
        let c: Vec<_> = row.split('\t').collect();
        assert_eq!(c.len(), 10);
        let iq = fs::read(root.join(format!("{}.cs8", c[0]))).unwrap();
        assert_eq!(hex(&Sha256::digest(&iq)), c[5]);
        let number = |i: usize| c[i].parse::<usize>().unwrap();
        assert_eq!(iq.len(), 2 * number(6));
        assert_eq!(number(2), 16);
        assert_eq!(number(7), 37 + 480);
        assert_eq!(number(8), number(7) + 80 * number(3));
        assert_eq!(number(6), number(8) + 64);
        let psdu: Vec<_> = (0..c[4].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&c[4][i..i + 2], 16).unwrap())
            .collect();
        let end = psdu.len() - 4;
        assert_eq!(
            crc(&psdu[..end]),
            u32::from_le_bytes(psdu[end..].try_into().unwrap())
        );
        assert!(number(1) < 8 && number(9) < 2);
        assert!([100, 4095].contains(&psdu.len()));
        assert!(matrix.insert((number(1), number(9), psdu.len(), c[0].ends_with("offset"))));
    }
    assert_eq!(matrix.len(), 64);
}

#[test]
fn radio_sampling_clock_exact_frame_recovery() {
    use crafter::radio::*;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("ofdm-clock-manifest.json")).unwrap()).unwrap();
    let mut failures = Vec::new();
    for fixture in manifest["fixtures"].as_array().unwrap() {
        let name = fixture["name"].as_str().unwrap();
        let bytes = fs::read(root.join(format!("{name}.cs8"))).unwrap();
        let mut coordinates = None;
        for chunk in [127, 65536] {
            let config = RxConfig {
                sample_rate_hz: 20_000_000,
                center_frequency_hz: 2_412_000_000,
                max_chunk_samples: chunk,
                max_buffer_samples: 120_000,
                max_frame_bytes: 4095,
                max_pending_frames: 4,
                max_capture_samples: 200_000,
                max_duration: std::time::Duration::from_secs(1),
            };
            let position = IqPosition {
                epoch: 7,
                sequence: 0,
                sample_index: 1_000_000,
                time_anchor: None,
                discontinuity: None,
            };
            let mut source =
                ReaderIqSource::new(std::io::Cursor::new(&bytes), config, position).unwrap();
            let mut decoder = LegacyOfdmDecoder::new();
            let mut frames = Vec::new();
            loop {
                let event = source.next_event().unwrap();
                let end = matches!(event, IqEvent::End(_));
                frames.extend(decoder.consume(event).unwrap().frames);
                if end {
                    break;
                }
            }
            if frames.len() != 1
                || hex(&frames[0].bytes) != fixture["psdu_hex"].as_str().unwrap()
                || frames[0].integrity != FrameIntegrity::ValidFcs
            {
                failures.push(format!("{name} chunk={chunk} frames={}", frames.len()));
            } else {
                let frame = &frames[0];
                let tracking = frame
                    .diagnostics
                    .iter()
                    .find_map(|d| match d {
                        PhyDiagnostic::OfdmTracking {
                            sampling_clock_offset_ppm,
                            pilot_residual_rms_rad,
                            data_symbols,
                        } => Some((
                            *sampling_clock_offset_ppm,
                            *pilot_residual_rms_rad,
                            *data_symbols,
                        )),
                        _ => None,
                    })
                    .expect("tracking metadata");
                assert!(
                    tracking.1.is_finite() && tracking.1 >= 0. && tracking.1 < 0.2,
                    "{name}: {tracking:?}"
                );
                let ppm = tracking.0.expect("multiple DATA symbols");
                assert!(ppm.is_finite());
                if name.contains("max_length") {
                    let expected = fixture["receiver_clock_ppm"].as_i64().unwrap() as f32;
                    assert!(
                        (ppm - expected).abs() < 2.,
                        "{name}: measured {ppm}, expected {expected}"
                    );
                }
                assert_eq!(frame.start.epoch, 7);
                assert_eq!(
                    frame.start.sample_index,
                    1_000_000 + fixture["preamble_start"].as_u64().unwrap(),
                    "{name}"
                );
                let current = (frame.start.sample_index, frame.end_sample_index);
                if let Some(previous) = coordinates {
                    assert_eq!(current, previous, "{name}");
                }
                coordinates = Some(current);
                // The receiver reports its consumed FFT extent, in original
                // source coordinates, not a resampled or zero-based timeline.
                let bits = frame.bytes.len() * 8 + 22;
                let symbols = bits.div_ceil(frame.rate_bps as usize / 250_000);
                assert_eq!(tracking.2, symbols);
                assert_eq!(
                    frame.end_sample_index,
                    frame.start.sample_index + 400 + symbols as u64 * 80
                );
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Deliberately byte-oriented MAC CRC; fixture generation uses Python zlib.
fn crc(bytes: &[u8]) -> u32 {
    let mut value = !0u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb88320 & (0u32.wrapping_sub(value & 1)));
        }
    }
    !value
}

#[test]
fn radio_sampling_clock_vector_inventory_and_integrity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("ofdm-clock-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["schema"], "crafter.radio.ofdm-clock/v1");
    assert_eq!(manifest["sample_rate_hz"], 20_000_000);
    assert_eq!(manifest["format"], "cs8");
    let fixtures = manifest["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 48);
    let mut combinations = std::collections::BTreeSet::new();
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let rate = fixture["rate_mbps"].as_u64().unwrap();
        let ppm = fixture["receiver_clock_ppm"].as_i64().unwrap();
        assert!([6, 9, 12, 18, 24, 36, 48, 54].contains(&rate));
        assert!([-20, 0, 20].contains(&ppm));
        assert_eq!(fixture["cfo_hz"], 0);
        let maximum = name.contains("max_length");
        assert!(combinations.insert((rate, ppm, maximum)));
        let iq = fs::read(root.join(format!("{name}.cs8"))).unwrap();
        assert_eq!(
            iq.len() as u64,
            2 * fixture["sample_count"].as_u64().unwrap()
        );
        assert_eq!(
            hex(&Sha256::digest(&iq)),
            fixture["sha256"].as_str().unwrap()
        );
        let encoded = fixture["psdu_hex"].as_str().unwrap();
        assert_eq!(encoded.len() % 2, 0);
        let psdu: Vec<u8> = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(psdu.len() == 4095, maximum);
        let split = psdu.len() - 4;
        assert_eq!(
            crc(&psdu[..split]),
            u32::from_le_bytes(psdu[split..].try_into().unwrap())
        );
        let symbols = (16 + 8 * psdu.len() + 6).div_ceil(rate as usize * 4);
        let origin = fixture["preamble_start"].as_u64().unwrap();
        let ratio = 1.0 + ppm as f64 * 1e-6;
        let expected_end = (origin as f64 + (400 + 80 * symbols) as f64 * ratio).ceil() as u64;
        assert_eq!(fixture["frame_end"], expected_end);
        assert_eq!(
            fixture["sample_count"],
            (origin as f64 + (432 + 80 * symbols) as f64 * ratio).ceil() as u64
        );
    }
    for (field, file) in [
        ("generator_sha256", "ofdm_clock_vectors.py"),
        ("encoder_sha256", "ofdm_vectors.py"),
    ] {
        let source = root
            .join("../../../../tools/oracle/engine/backends")
            .join(file);
        assert_eq!(
            manifest[field].as_str().unwrap(),
            hex(&Sha256::digest(fs::read(source).unwrap()))
        );
    }
}

#[test]
fn radio_independent_vector_inventory_and_integrity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let index = fs::read_to_string(root.join("ofdm-index.tsv")).unwrap();
    let rates = [6, 9, 12, 18, 24, 36, 48, 54];
    assert_eq!(crc(b"123456789"), 0xcbf43926);
    assert_eq!(index.lines().skip(1).count(), 20);
    for (i, line) in index.lines().skip(1).enumerate() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 10);
        let name = fields[0];
        let number = |n: usize| fields[n].parse::<usize>().unwrap();
        let samples = fs::read(root.join(format!("{name}.cs8"))).unwrap();
        assert_eq!(samples.len(), number(5) * 2);
        assert_eq!(hex(&Sha256::digest(&samples)), fields[7]);
        let psdu: Vec<u8> = fields[6]
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let split = psdu.len() - 4;
        let received = u32::from_le_bytes(psdu[split..].try_into().unwrap());
        assert_eq!(crc(&psdu[..split]) == received, fields[8] == "True");
        assert_eq!(number(4), (16 + 8 * psdu.len() + 6).div_ceil(number(3)));
        let full_samples = 37 + 400 + 80 * number(4) + 32;
        assert_eq!(
            number(5),
            full_samples - if name.ends_with("truncated") { 73 } else { 0 }
        );
        if i < 8 {
            assert_eq!(number(1), rates[i]);
            assert_eq!(fields[9], "frame");
            assert_eq!(number(2), [1, 1, 2, 2, 4, 4, 6, 6][i]);
        }
        if i == 0 {
            // Fixed independently generated golden FCS, not calculated from fixture metadata.
            assert_eq!(received, 0x2dc356fb);
        }
        let intermediate = fs::read_to_string(root.join(format!("{name}.json"))).unwrap();
        for key in [
            "signal",
            "signal_coded",
            "signal_interleaved",
            "data",
            "scrambled",
            "coded",
            "punctured",
            "interleaved",
        ] {
            assert!(intermediate.contains(&format!("\"{key}\":")));
        }
    }
    let manifest = fs::read_to_string(root.join("ofdm-manifest.json")).unwrap();
    assert!(manifest.contains("\"sample_rate_hz\": 20000000"));
    assert!(manifest.contains("\"generator_version\": \"6\""));
}
