//! The production genesis ceremony (`tools/genesis-v5.mjs`) makes a genesis
//! that this node starts from and runs: the CometBFT file parses, the
//! application state has the node's own bytes and network id, InitChain
//! accepts the twenty validators at the production power and sets the
//! consensus parameters the file states, and blocks signed by all twenty
//! commit and pay their owners.
//! Needs `node` on the path; skipped where there is none.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::process::Command;
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::Account;
use timecurrency_v5::{app::App, engine, genesis::Genesis};

const ACCEPT: i32 = response_process_proposal::ProposalStatus::Accept as i32;

/// Production genesis files from the ceremony tool, with twenty fresh
/// validators: the protocol-4 fee choices, and a lower fee paid on in full.
fn ceremonies() -> Option<Vec<serde_json::Value>> {
    let module = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tools")
        .join("genesis-v5.mjs");
    let script = r#"import {pathToFileURL} from 'node:url';
import {createHash, generateKeyPairSync, randomBytes, sign} from 'node:crypto';
const tool = await import(pathToFileURL(process.env.GENESIS_MODULE).href);
const key = () => generateKeyPairSync('ed25519').publicKey.export({format: 'der', type: 'spki'}).subarray(-32).toString('hex');
const entries = Array.from({length: 20}, (_, i) => {
  const pair = generateKeyPairSync('ed25519');
  const consensus = pair.publicKey.export({format: 'der', type: 'spki'}).subarray(-32).toString('hex');
  const owner = key();
  const entry = {schema_version: 1, kind: 'time-v5-validator-entry', chain_id: 'time-devnet-v4-prod-rehearsal',
    organization: 'Org ' + i, account_name: 'op_' + i, owner_public_key_hex: owner, consensus_public_key_hex: consensus,
    consensus_address: createHash('sha256').update(Buffer.from(consensus, 'hex')).digest().subarray(0, 20).toString('hex').toUpperCase(),
    node_id: randomBytes(20).toString('hex'), commission_bps: 1000, provider: 'aws', region: 'eu-west-3',
    account_security: tool.accountSecurity({paymentPublicKeyHex: owner, loginPublicKeyHex: key(), recoveryPublicKeysHex: [key(), key()], dailyLimitSeconds: '3600'})};
  return {...entry, consensus_signature: sign(null, tool.entryMessage(entry), pair.privateKey).toString('base64')};
});
const out = [];
for (const fees of [{}, {feeMicros: '10', feesToValidatorsPpm: '1000000'}]) {
  const ceremony = tool.makeCeremony({chainId: 'time-devnet-v4-prod-rehearsal', genesisTime: '2030-01-01T00:00:00.000Z', now: Date.parse('2029-12-01T00:00:00.000Z'), ...fees});
  const built = tool.buildProductionGenesis({ceremony, entries});
  out.push({file: built.genesisBytes.toString(), app_state: JSON.stringify(built.genesis.app_state), network_id: built.networkId, sha256: built.genesisSha256, fee: ceremony.fee_micros});
}
console.log(JSON.stringify(out));
"#;
    let Ok(output) = Command::new("node")
        .args(["--input-type=module", "-e", script])
        .env("GENESIS_MODULE", &module)
        .output()
    else {
        eprintln!("skipped: node is not on the path");
        return None;
    };
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    Some(serde_json::from_slice(&output.stdout).unwrap())
}

fn timestamp(micros: i64) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: micros / 1_000_000,
        nanos: ((micros % 1_000_000) * 1000) as i32,
    })
}

#[test]
fn a_production_genesis_starts_and_runs() {
    let Some(cases) = ceremonies() else { return };
    assert_eq!(cases.len(), 2);
    for case in &cases {
        let file = case["file"].as_str().unwrap();
        let app_state = case["app_state"].as_str().unwrap();
        assert_eq!(hex::encode(Sha256::digest(file.as_bytes())), case["sha256"].as_str().unwrap());

        // CometBFT's own reading of the file, by the same library the node links.
        let comet: tendermint::Genesis<serde_json::Value> = serde_json::from_str(file).unwrap();
        assert_eq!(comet.initial_height, 1);
        assert_eq!(comet.validators.len(), 20);
        // CometBFT hands the application the bytes of `app_state` as they are in the file.
        assert!(file.ends_with(&format!("\"app_state\":{app_state}}}")), "app_state is not the last field");

        // The application state is in the node's own encoding, so its network id is the one the tool wrote.
        let genesis: Genesis = serde_json::from_str(app_state).unwrap();
        assert_eq!(serde_json::to_string(&genesis).unwrap(), app_state, "the node writes these settings differently");
        assert_eq!(genesis.network_id().unwrap(), case["network_id"].as_str().unwrap());
        assert_eq!(genesis.profile, pos::Profile::Production);
        assert!(genesis.all_new_time_to_validators);
        // The five rules the production profile requires: without any of
        // them the node would refuse this genesis at InitChain, below.
        assert!(genesis.stake_handover && genesis.distinct_names && genesis.waits_survive_stops && genesis.protected_registration && genesis.service_records);
        assert!(
            app_state.contains(r#""stake_handover":true,"distinct_names":true,"waits_survive_stops":true,"protected_registration":true,"protected_accounts":[{"id":"0","keys":[{"public_key":""#),
            "the settings are not in the node's order"
        );
        // Every owner account starts protected, with waits of two days; the
        // list is followed only by the service records, the last thing the
        // node writes.
        assert_eq!(genesis.protected_accounts.len(), 20);
        assert!(app_state.ends_with(r#""policy":{"threshold":"2","daily_limit_micros":"3600000000","delay_seconds":"172800","freeze_seconds":"172800"}}],"service_records":true}"#));
        for (id, protected) in genesis.protected_accounts.iter().enumerate() {
            assert_eq!(protected.id, id as u64);
            assert_eq!(protected.keys.len(), 4);
            // The key the account is known by is its payment key.
            let identity = &genesis.ledger.accounts[id].public_key;
            assert!(protected.keys.iter().any(|key| &key.public_key == identity && key.role == timecurrency_v5::security::Role::Spend));
        }
        assert_eq!(genesis.fee().to_string(), case["fee"].as_str().unwrap());
        assert_eq!(genesis.ledger.chain_id, comet.chain_id.as_str());
        assert_eq!(
            i128::from(genesis.ledger.genesis_time_micros) * 1000,
            comet.genesis_time.unix_timestamp_nanos()
        );
        for (info, validator) in comet.validators.iter().zip(&genesis.validators) {
            let key = info.pub_key.ed25519().unwrap();
            assert_eq!(hex::encode(key.as_bytes()), validator.consensus_key, "CometBFT's order is the owners' order");
            assert_eq!(info.address.as_bytes(), &Sha256::digest(key.as_bytes())[..20]);
            assert_eq!(info.power.value(), genesis.profile.genesis_power());
        }

        // InitChain as CometBFT makes it from this file.
        let dir = tempfile::tempdir().unwrap();
        let app = App::open(dir.path().join("state.redb")).unwrap();
        let request = RequestInitChain {
            chain_id: comet.chain_id.to_string(),
            time: timestamp(genesis.ledger.genesis_time_micros),
            app_state_bytes: app_state.as_bytes().to_vec().into(),
            initial_height: 1,
            validators: comet
                .validators
                .iter()
                .map(|info| ValidatorUpdate {
                    pub_key: Some(tendermint_proto::crypto::PublicKey {
                        sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(
                            info.pub_key.ed25519().unwrap().as_bytes().to_vec(),
                        )),
                    }),
                    power: info.power.value() as i64,
                })
                .collect(),
            ..Default::default()
        };
        let init = app.try_init(request).unwrap();
        // The parameters the application sets are the ones the file states.
        let params = init.consensus_params.unwrap();
        let block = params.block.unwrap();
        let evidence = params.evidence.unwrap();
        assert_eq!(block.max_bytes as u64, comet.consensus_params.block.max_bytes);
        assert_eq!(block.max_gas, comet.consensus_params.block.max_gas);
        assert_eq!(evidence.max_age_num_blocks as u64, comet.consensus_params.evidence.max_age_num_blocks);
        assert_eq!(
            evidence.max_age_duration.unwrap().seconds as u64,
            comet.consensus_params.evidence.max_age_duration.0.as_secs()
        );
        assert_eq!(evidence.max_bytes, comet.consensus_params.evidence.max_bytes);
        assert_eq!(params.version.unwrap().app, comet.consensus_params.version.unwrap().app);

        // Blocks a minute apart, each signed by every validator of its height.
        // As in CometBFT, the updates a block returns take effect two heights
        // later, and the commit carried by block H is signed by the set of
        // height H - 1.
        let mut sets: Vec<Vec<Validator>> = vec![Vec::new(); 3];
        sets[1] = comet
            .validators
            .iter()
            .map(|info| Validator {
                address: info.address.as_bytes().to_vec().into(),
                power: info.power.value() as i64,
            })
            .collect();
        sets[2] = sets[1].clone();
        for height in 1..=6i64 {
            let request = RequestFinalizeBlock {
                height,
                time: timestamp(genesis.ledger.genesis_time_micros + height * 60_000_000),
                hash: Sha256::digest(height.to_be_bytes()).to_vec().into(),
                decided_last_commit: (height > 1).then(|| CommitInfo {
                    round: 0,
                    votes: sets[(height - 1) as usize]
                        .iter()
                        .map(|validator| VoteInfo {
                            validator: Some(validator.clone()),
                            block_id_flag: BlockIdFlag::Commit as i32,
                        })
                        .collect(),
                }),
                ..Default::default()
            };
            let proposal = RequestProcessProposal {
                txs: request.txs.clone(),
                proposed_last_commit: request.decided_last_commit.clone(),
                misbehavior: request.misbehavior.clone(),
                hash: request.hash.clone(),
                height: request.height,
                time: request.time,
                next_validators_hash: request.next_validators_hash.clone(),
                proposer_address: request.proposer_address.clone(),
            };
            assert_eq!(app.process_proposal(proposal).status, ACCEPT, "block {height}");
            let response = app.try_finalize(request).unwrap();
            app.try_commit().unwrap();
            let mut next = sets[height as usize + 1].clone();
            for update in &response.validator_updates {
                let Some(tendermint_proto::crypto::public_key::Sum::Ed25519(key)) =
                    update.pub_key.as_ref().and_then(|key| key.sum.as_ref())
                else {
                    panic!("validator update without an Ed25519 key");
                };
                let address: Vec<u8> = Sha256::digest(key)[..20].to_vec();
                next.retain(|validator| validator.address.as_ref() != address.as_slice());
                if update.power > 0 {
                    next.push(Validator { address: address.into(), power: update.power });
                }
            }
            sets.push(next);
        }
        assert_eq!(sets.len(), 9);

        // Every owner has been paid, so each can pay a fee: report a double
        // signer, give someone their first seconds. And each is protected
        // from the first block: four keys, none with every power, and a
        // security row a wallet is served with the account.
        for id in 0..20u64 {
            // One account per query: a query selects at most eight.
            let response = app.query(RequestQuery {
                data: serde_json::to_vec(&serde_json::json!({ "ids": [id.to_string()], "include_security": true }))
                    .unwrap()
                    .into(),
                path: "/v4/state".into(),
                height: 0,
                prove: false,
            });
            assert_eq!(response.code, 0, "{}", response.log);
            let view: serde_json::Value = serde_json::from_slice(&response.value).unwrap();
            let key = hex::encode(engine::account_key(id));
            let entry = view["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["key_hex"] == key.as_str())
                .unwrap_or_else(|| panic!("account {id} missing"));
            let account: Account = serde_json::from_slice(
                &STANDARD.decode(entry["value_b64"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            assert!(account.balance >= genesis.fee(), "owner {id} holds {} micros", account.balance);
            assert_eq!(account.devices.len(), 4);
            assert!(account.devices.iter().all(|device| !(device.can_manage && device.can_spend)), "owner {id} has a key with every power");
            let row = hex::encode(timecurrency_v5::security::key(id));
            let served = view["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["key_hex"] == row.as_str())
                .unwrap_or_else(|| panic!("the security row of owner {id} is not served"));
            let security: timecurrency_v5::security::Security =
                serde_json::from_slice(&STANDARD.decode(served["value_b64"].as_str().unwrap()).unwrap()).unwrap();
            assert_eq!((security.version, security.policy.threshold, security.policy.delay_seconds), (1, 2, 172_800));
            if id == 0 {
                // The network counts its stops from the first block: none
                // so far. The number comes with every answer, in the
                // metadata row.
                let meta_key = hex::encode(b"meta");
                let meta = view["entries"].as_array().unwrap().iter().find(|entry| entry["key_hex"] == meta_key.as_str()).unwrap();
                let meta: serde_json::Value =
                    serde_json::from_slice(&STANDARD.decode(meta["value_b64"].as_str().unwrap()).unwrap()).unwrap();
                assert_eq!(meta["stopped_micros"], "0");
            }
        }
    }
}

/// The tool refuses exactly the keys the node refuses: a key it accepted and the
/// node refused would let one entry make a genesis that every operator checks
/// and none can start. Candidates: the eight points of small order, random
/// bytes, real keys, and real keys moved by a point of small order.
#[test]
fn the_tool_accepts_the_keys_the_node_accepts() {
    use curve25519_dalek::{constants::EIGHT_TORSION, edwards::CompressedEdwardsY};
    use std::io::Write;
    let mut candidates: Vec<[u8; 32]> = EIGHT_TORSION.iter().map(|point| point.compress().to_bytes()).collect();
    let mut seed = [7u8; 32];
    for i in 0..2000u32 {
        seed = Sha256::digest([&seed[..], &i.to_be_bytes()].concat()).into();
        candidates.push(seed);
    }
    for i in 0..50u8 {
        let key = ed25519_dalek::SigningKey::from_bytes(&[i.wrapping_add(1); 32]).verifying_key().to_bytes();
        candidates.push(key);
        let moved = CompressedEdwardsY(key).decompress().unwrap() + EIGHT_TORSION[usize::from(i % 7 + 1)];
        candidates.push(moved.compress().to_bytes());
    }
    let module = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tools")
        .join("genesis-v5.mjs");
    let script = r#"import {pathToFileURL} from 'node:url';
const {ed25519Point} = await import(pathToFileURL(process.env.GENESIS_MODULE).href);
let input = '';
for await (const chunk of process.stdin) input += chunk;
console.log(JSON.stringify(JSON.parse(input).map(ed25519Point)));
"#;
    let Ok(mut child) = Command::new("node")
        .args(["--input-type=module", "-e", script])
        .env("GENESIS_MODULE", &module)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    else {
        eprintln!("skipped: node is not on the path");
        return;
    };
    let hex_list: Vec<String> = candidates.iter().map(hex::encode).collect();
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(&hex_list).unwrap()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let answers: Vec<bool> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(answers.len(), candidates.len());
    let mut accepted = 0;
    for (bytes, tool) in candidates.iter().zip(answers) {
        let node = ed25519_dalek::VerifyingKey::from_bytes(bytes).map(|key| !key.is_weak()).unwrap_or(false);
        assert_eq!(tool, node, "the tool and the node disagree on {}", hex::encode(bytes));
        accepted += usize::from(node);
    }
    // Both kinds occur among the candidates: the comparison is not vacuous.
    assert!(accepted > 1000 && accepted < candidates.len() - 8, "{accepted}");
}
