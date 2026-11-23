//! The campaign's JavaScript genesis builder (`campaign/lib/genesis.mjs`) and
//! the node write the same bytes, and so compute the same network id, with
//! and without the optional settings. The network id is a hash of those
//! bytes, so a difference would start test networks whose id no wallet pins.
//! Needs `node` on the path; skipped where there is none.
use std::process::Command;
use timecurrency_v5::genesis::Genesis;

/// The settings of `spec/settings.md` that the builder writes: its word for
/// each and the node's field, in the order in which the node writes them.
const SETTINGS: [(&str, &str); 4] = [
    ("distinctNames", "distinct_names"),
    ("waitsSurviveStops", "waits_survive_stops"),
    ("protectedRegistration", "protected_registration"),
    ("serviceRecords", "service_records"),
];

#[test]
fn the_campaign_genesis_has_the_node_bytes_and_network_id() {
    let module = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("campaign")
        .join("lib")
        .join("genesis.mjs");
    let script = format!(
        r#"import {{pathToFileURL}} from 'node:url';
import {{generateKeyPairSync}} from 'node:crypto';
const {{buildGenesis, GENESIS_SETTINGS}} = await import(pathToFileURL(process.env.GENESIS_MODULE).href);
const identity = (_, i) => ({{address: String(i).repeat(40), pub_key: {{type: 'tendermint/PubKeyEd25519', value: generateKeyPairSync('ed25519').publicKey.export({{format: 'der', type: 'spki'}}).subarray(-32).toString('base64')}}}});
const identities = Array.from({{length: 4}}, identity);
// Seven validators, the fewest with which the starting validators' lent power can end.
const seven = Array.from({{length: 7}}, identity);
const consensusParams = {{block: {{max_bytes: '1', max_gas: '-1'}}, evidence: {{max_age_num_blocks: '1', max_age_duration: '1', max_bytes: '1'}}, validator: {{pub_key_types: ['ed25519']}}, version: {{app: '0'}}, abci: {{}}}};
const out = [];
for (const options of [{{}}, {{feeMicros: 10}}, {{feeMicros: 1}}, {{feeMicros: 1000}}, {{feesToValidatorsPpm: 1000000}}, {{feesToValidatorsPpm: 1000000, feeMicros: 10}}, {{feeMicros: 999, feesToValidatorsPpm: 5}}]) {{
  const g = buildGenesis({{identities, consensusParams, ...options}});
  out.push({{options, id: g.networkId, bytes: JSON.stringify(g.manifest.genesis)}});
}}
for (const options of [{{allNewTimeToValidators: false}}, {{allNewTimeToValidators: true}}, {{allNewTimeToValidators: true, feeMicros: 10, feesToValidatorsPpm: 1000000}}, {{stakeHandover: true}}, {{allNewTimeToValidators: true, feeMicros: 10, feesToValidatorsPpm: 1000000, stakeHandover: true}}, {{distinctNames: true}}, {{distinctNames: false}}, {{stakeHandover: true, distinctNames: true}}, {{allNewTimeToValidators: true, feeMicros: 10, feesToValidatorsPpm: 1000000, stakeHandover: true, distinctNames: true}}]) {{
  const g = buildGenesis({{identities: seven, consensusParams, ...options}});
  out.push({{options, id: g.networkId, bytes: JSON.stringify(g.manifest.genesis)}});
}}
const five = buildGenesis({{identities: seven.slice(0, 5), consensusParams, allNewTimeToValidators: true}});
out.push({{options: {{allNewTimeToValidators: true, validators: 5}}, id: five.networkId, bytes: JSON.stringify(five.manifest.genesis)}});
// The settings of spec/settings.md (waitsSurviveStops, protectedRegistration and serviceRecords besides distinctNames):
// each alone and in every combination; each asked for with false; all of them with every other option a campaign gives.
const words = GENESIS_SETTINGS.map(([option]) => option);
for (let mask = 0; mask < 2 ** words.length; mask++) {{
  const options = Object.fromEntries(words.filter((_, k) => mask & (1 << k)).map((option) => [option, true]));
  const g = buildGenesis({{identities: seven, consensusParams, ...options}});
  out.push({{options, id: g.networkId, bytes: JSON.stringify(g.manifest.genesis)}});
}}
for (const options of [Object.fromEntries(words.map((option) => [option, false])), {{allNewTimeToValidators: true, feeMicros: 10, feesToValidatorsPpm: 1000000, stakeHandover: true, ...Object.fromEntries(words.map((option) => [option, true]))}}]) {{
  const g = buildGenesis({{identities: seven, consensusParams, ...options}});
  out.push({{options, id: g.networkId, bytes: JSON.stringify(g.manifest.genesis)}});
}}
out.push({{settings: GENESIS_SETTINGS}});
let refused = false;
try {{ buildGenesis({{identities, consensusParams, allNewTimeToValidators: true}}); }} catch {{ refused = true; }}
out.push({{refused}});
console.log(JSON.stringify(out));
"#
    );
    let Ok(output) = Command::new("node")
        .args(["--input-type=module", "-e", &script])
        .env("GENESIS_MODULE", &module)
        .output()
    else {
        eprintln!("skipped: node is not on the path");
        return;
    };
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let cases: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 37);
    assert_eq!(cases[36]["refused"], true, "four validators with all new time to validators");
    // The builder writes the settings this test knows, in this order, and no
    // other: a setting added to the builder alone fails here.
    let written: Vec<(String, String)> = serde_json::from_value(cases[35]["settings"].clone()).unwrap();
    assert_eq!(written, SETTINGS.map(|(option, field)| (option.to_string(), field.to_string())), "GENESIS_SETTINGS of campaign/lib/genesis.mjs");
    let mut with = [0; 4];
    for case in &cases[..35] {
        let bytes = case["bytes"].as_str().unwrap();
        let genesis: Genesis = serde_json::from_str(bytes).unwrap_or_else(|e| panic!("{}: {e}", case["options"]));
        assert_eq!(serde_json::to_string(&genesis).unwrap(), bytes, "bytes differ for {}", case["options"]);
        assert_eq!(genesis.network_id().unwrap(), case["id"].as_str().unwrap(), "network id differs for {}", case["options"]);
        let expected = case["options"]["feeMicros"].as_u64().unwrap_or(1000);
        assert_eq!(genesis.fee(), expected);
        let all = case["options"]["allNewTimeToValidators"].as_bool().unwrap_or(false);
        assert_eq!(genesis.all_new_time_to_validators, all, "{}", case["options"]);
        let handover = case["options"]["stakeHandover"].as_bool().unwrap_or(false);
        assert_eq!(genesis.stake_handover, handover, "{}", case["options"]);
        // The settings of spec/settings.md: each is set exactly when it was
        // asked for and written only then, in the node's order after every
        // other field, and the last one asked for is the last field of all.
        // The harness lists no account that starts protected: only the
        // production ceremony does, between protected_registration and
        // service_records.
        let flags = [genesis.distinct_names, genesis.waits_survive_stops, genesis.protected_registration, genesis.service_records];
        let mut last: Option<(usize, &str)> = None;
        for (k, (&(option, field), flag)) in SETTINGS.iter().zip(flags).enumerate() {
            let asked = case["options"][option].as_bool().unwrap_or(false);
            assert_eq!(flag, asked, "{field} for {}", case["options"]);
            assert_eq!(bytes.contains(&format!("\"{field}\"")), asked, "{field} in the bytes for {}", case["options"]);
            if asked {
                let at = bytes.find(&format!(",\"{field}\":true")).unwrap();
                assert!(last.is_none_or(|(before, _)| before < at), "{field} before a setting the node writes first, for {}", case["options"]);
                last = Some((at, field));
                with[k] += 1;
            }
        }
        assert!(genesis.protected_accounts.is_empty(), "{}", case["options"]);
        if let Some((_, field)) = last {
            assert!(bytes.ends_with(&format!(",\"{field}\":true}}")), "{field} is not the last field for {}", case["options"]);
            // A laboratory genesis takes every combination: the node would
            // start it. With distinct_names the harness's own account names
            // pass the node's check of them (`network_id`, above, validates
            // the genesis).
            genesis.validate_new().unwrap_or_else(|e| panic!("{}: {e}", case["options"]));
        }
        if genesis.distinct_names {
            assert_eq!(genesis.ledger.accounts.len(), 64);
        }
    }
    // distinct_names: the three cases of before, the eight combinations that
    // hold it and the campaign's; each other setting: eight and the campaign's.
    assert_eq!(with, [12, 9, 9, 9]);
}
