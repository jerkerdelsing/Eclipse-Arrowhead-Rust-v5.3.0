// SPDX-License-Identifier: EPL-2.0
use arrowhead_core_rust::{Database, Store, authorization, table};
use serde_json::{Value, json};
fn request() -> Value {
    json!({"provider":"TestProvider","cloud":"LOCAL","targetType":"SERVICE_DEF","target":"testSignal","defaultPolicy":{"policyType":"WHITELIST","policyList":["TestConsumer"]},"scopedPolicies":{"read-value":{"policyType":"ALL"}}})
}
#[test]
fn canonical_grant_names_are_preserved_and_invalid_names_do_not_write() {
    let long_system = "S".repeat(63);
    let too_long_system = "S".repeat(64);
    let long_target = "s".repeat(63);
    let too_long_target = "s".repeat(64);
    let long_scope = "r".repeat(63);
    let too_long_scope = "r".repeat(64);
    let cases = vec![
        ("provider", "S", true),
        ("provider", "System2", true),
        ("provider", long_system.as_str(), true),
        ("provider", "lowercase", false),
        ("provider", "bad_provider", false),
        ("provider", "Bad-Provider", false),
        ("provider", "System\n", false),
        ("provider", "Systém", false),
        ("provider", too_long_system.as_str(), false),
        ("target", "s", true),
        ("target", "service2Value", true),
        ("target", long_target.as_str(), true),
        ("target", "Uppercase", false),
        ("target", "bad_signal", false),
        ("target", "bad-signal", false),
        ("target", "signal\n", false),
        ("target", "sıgnal", false),
        ("target", too_long_target.as_str(), false),
        ("scope", "r", true),
        ("scope", "read-value2", true),
        ("scope", long_scope.as_str(), true),
        ("scope", "Uppercase", false),
        ("scope", "bad_scope", false),
        ("scope", "badScope", false),
        ("scope", "-read", false),
        ("scope", "read-", false),
        ("scope", "read--value", false),
        ("scope", "1read", false),
        ("scope", "read\n", false),
        ("scope", "réad", false),
        ("scope", too_long_scope.as_str(), false),
    ];
    for target_type in ["SERVICE_DEF", "EVENT_TYPE"] {
        for (field, value, valid) in &cases {
            let mut req = request();
            req["targetType"] = target_type.into();
            if *field == "scope" {
                req["scopedPolicies"] = json!({(*value):{"policyType":"ALL"}});
            } else {
                req[*field] = (*value).into();
            }
            let mut db = Database::new();
            let result = authorization::grant(&mut db, req, "MGMT", "TestOperator");
            if *valid {
                let row = result.unwrap_or_else(|e| panic!("canonical {field} rejected: {e:?}"));
                if *field != "scope" {
                    assert_eq!(row[*field], *value);
                }
            } else {
                assert!(
                    result.is_err(),
                    "noncanonical {target_type} {field} {value:?} accepted"
                );
                assert!(table(&mut db, "policies").is_empty());
            }
        }
    }
}
#[test]
fn policy_lists_require_canonical_system_names() {
    for kind in ["WHITELIST", "BLACKLIST"] {
        for name in [
            "lowercase".into(),
            "bad_consumer".into(),
            "Bad-Consumer".into(),
            "Consumer\n".into(),
            "Cónsumer".into(),
            "C".repeat(64),
        ] {
            let mut req = request();
            req["defaultPolicy"] = json!({"policyType":kind,"policyList":["TestConsumer",name]});
            let mut db = Database::new();
            assert!(authorization::grant(&mut db, req, "MGMT", "TestOperator").is_err());
            assert!(table(&mut db, "policies").is_empty());
        }
    }
}
#[test]
fn invalid_name_rolls_back_whole_batch_and_preserves_existing_policies() {
    let store = Store::memory();
    store
        .update(|db| {
            authorization::grant(db, request(), "MGMT", "TestOperator")?;
            Ok(())
        })
        .unwrap();
    let before = store.snapshot();
    let result = store.update(|db| {
        let mut req = request();
        req["target"] = "anotherSignal".into();
        authorization::grant(db, req, "MGMT", "TestOperator")?;
        let mut req = request();
        req["provider"] = "bad_provider".into();
        authorization::grant(db, req, "MGMT", "TestOperator")?;
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(store.snapshot(), before);
}
