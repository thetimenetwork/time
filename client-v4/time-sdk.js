/* Local devnet SDK. Keys remain in the wallet; verification must fail closed. */
(function (root) {
  'use strict';
  const utf8 = new TextEncoder();
  const MAX_U64 = (1n << 64n) - 1n;
  const KINDS = Object.freeze({ commit: 1, reveal: 2, transfer: 3, bid: 4, delegate: 5, undelegate: 6, withdraw: 7, add_device: 8, revoke_device: 9, merchant_payment: 10, set_recovery: 11, consent_recovery: 12, approve_recovery: 13, cancel_recovery: 14, finalize_recovery: 15, cancel_pending: 16, register_validator:17, self_bond:18, self_unbond:19, double_vote:20, withdraw_stake:21, retire_validator:24, bitcoin_headers:40, bitcoin_bid:41, claim_auction:42, sponsor_registration:44, register_protected:45, treasury_propose:60, treasury_activate:61, treasury_control:62, secure_account:70, signin_keys:71, freeze_account:72, root_operation:73, finalize_replacement:74, waiting_payment:75, cancel_waiting:76, daily_limit:77, upgrade_signal:80 });
  const FIELDS = { 1: ['commitment', 'expires_elapsed_micros'], 2: ['name', 'salt'], 3: ['to', 'amount'], 4: ['epoch', 'weight'], 5: ['operator', 'amount', 'min_shares'], 6: ['operator', 'shares', 'min_amount'], 7: ['entry'], 8: ['public_key', 'can_manage', 'can_spend', 'proof'], 9: ['public_key'], 10: ['to', 'amount', 'reference'], 11: ['guardians', 'threshold', 'delay_seconds'], 12: ['target', 'policy_version', 'accept'], 13: ['target', 'policy_version', 'recovery_id', 'new_public_key', 'expires_elapsed_micros', 'proof'], 14: [], 15: ['recovery_id'], 16: [] };
  const DECIMALS = new Set(['to', 'amount', 'epoch', 'weight', 'operator', 'shares', 'entry', 'expires_elapsed_micros', 'min_shares', 'min_amount', 'threshold', 'delay_seconds', 'target', 'policy_version']);
  function invariant(value, message) { if (!value) throw new Error(message); }
  function decimal(value) { invariant(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) <= MAX_U64, 'Expected a canonical u64 decimal string'); return value; }
  // Protocol versions.
  // - The first version of a network is the one in its genesis and in the trust manifest ('4'). It
  //   never changes: a trust manifest is not reissued for an upgrade, and the gateway's
  //   /api/network keeps reporting it.
  // - The version in force is read from verified state only: `state.protocol_version`, which the
  //   verifier has checked against the header the validators certified. Never from a gateway.
  // - This build implements the versions listed in IMPLEMENTED. A later one is refused with an
  //   error whose message begins `UPGRADE_REQUIRED:` (like `CHECKPOINT_REFRESH_REQUIRED:` and
  //   `STALE_STATE:`) and whose `code` is 'UPGRADE_REQUIRED'.
  // - That `code` is set in exactly two places: by proof-verifier.mjs, on a refusal the compiled
  //   verifier itself threw, and by requireKnownVersion below. An error that repeats what a
  //   gateway said never carries it, whatever the gateway sent (see `request`). Whoever shows
  //   "update this app" or sends an alert for it tests the code, never the words.
  const FIRST_VERSION = '4';
  // Each implemented version with the hash of its specification (`spec/protocol-N.md`). A plan
  // names both, and a program with other rules under the same number has another hash. The first
  // version is never the subject of a plan, so its hash is not needed here.
  const IMPLEMENTED = Object.freeze([Object.freeze({ version: '4', spec: null })]);
  const KNOWN_VERSIONS = Object.freeze(IMPLEMENTED.map(item => item.version));
  function isVersion(value) { return typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= MAX_U64; }
  // Whether a version is the network's first one or a later one. A rule that came with version 4
  // holds from then on: a version never changes what an existing action means.
  function sinceFirstVersion(value) { return isVersion(value) && BigInt(value) >= BigInt(FIRST_VERSION); }
  function knowsVersion(value) { return KNOWN_VERSIONS.includes(value); }
  // Whether this build implements a scheduled plan: its version under exactly its specification.
  function knowsPlan(plan) { return IMPLEMENTED.some(item => item.spec !== null && item.version === plan?.version && item.spec === plan?.spec); }
  function upgradeRequired(version) {
    const error = new Error(`UPGRADE_REQUIRED: the network runs protocol version ${version}; this software implements versions ${KNOWN_VERSIONS[0]} to ${KNOWN_VERSIONS[KNOWN_VERSIONS.length - 1]}. Install a release that implements version ${version}.`);
    error.code = 'UPGRADE_REQUIRED'; return error;
  }
  // Whether an error is the refusal of a version this software does not implement: it carries
  // the code, which only the installed verifier's wrapper and requireKnownVersion set. The words
  // alone are never enough; a gateway can send any words.
  function isUpgradeRequired(error) { return typeof error === 'object' && error !== null && error.code === 'UPGRADE_REQUIRED' && typeof error.message === 'string' && error.message.startsWith('UPGRADE_REQUIRED:'); }
  // An error that repeats what a gateway said. Whatever JSON value the gateway sent (a string, an
  // array, an object, a number) becomes one string; the error is marked `gateway: true` and has
  // no `code`. Text that names UPGRADE_REQUIRED is also prefixed, for whoever reads it.
  function gatewayRefusal(value) {
    let text;
    try { text = typeof value === 'string' ? value : JSON.stringify(value); } catch { text = undefined; }
    if (typeof text !== 'string' || !text) text = 'The gateway refused the request';
    if (/UPGRADE_REQUIRED/i.test(text)) text = 'The gateway reports: ' + text;
    const error = new Error(text); error.gateway = true; return error;
  }
  // ---- A service that is busy (the web audit's W-9; seen on a trial network on 24 November 2026, where a proxy's limit
  // per caller refused 9 requests of 1,130 and twelve steps of a check failed for them).
  // A proxy, a gateway or an API refuses a request for load with status 429 (too many requests from this caller) or 503
  // (busy), and may say in Retry-After how many whole seconds to wait. Such an answer is told by its STATUS alone,
  // before anything of it is read: it is never a finding about the network, its body is never parsed or shown, and the
  // request it refused was not acted on, so it may be sent again. The numbers:
  // - tries: at most 4 sends of one read, the first included;
  // - budgetMs: 20 seconds for one read from its first send, so that an action that waits says something in that time;
  // - submitBudgetMs: 30 seconds to send a signed action (the same bytes), protectiveBudgetMs: 2 minutes for one that
  //   protects an account (a freeze, a cancellation, new recovery keys), with at most submitTries sends;
  // - minMs and maxMs: a wait is 1 to 30 seconds, whatever Retry-After says;
  // - firstMs: without Retry-After, 2 seconds, then 4, 8 and 16 (capped at maxMs);
  // - jitter: each wait is lengthened by up to a quarter, never shortened below what was asked, so that wallets behind
  //   one address that were refused together do not all ask again in the same instant.
  const BUSY = Object.freeze({ tries: 4, budgetMs: 20000, submitBudgetMs: 30000, protectiveBudgetMs: 120000, submitTries: 10, minMs: 1000, maxMs: 30000, firstMs: 2000, jitter: 0.25 });
  function busyStatus(status) { return status === 429 || status === 503; }
  // Retry-After in whole seconds (the form the proxy, the gateway and the API send), held to 1 to 30 seconds; null when
  // absent or not in that form.
  function retryAfterMs(value) {
    const seconds = String(value ?? '').trim();
    if (!/^[0-9]{1,6}$/.test(seconds)) return null;
    return Math.min(BUSY.maxMs, Math.max(BUSY.minMs, Number(seconds) * 1000));
  }
  // How long to wait before send number `attempt + 1` after a busy answer: Retry-After when given, else 2, 4, 8, 16 s;
  // plus up to a quarter more (`random` in [0, 1)); never more than 30 s.
  function busyDelayMs(retryAfter, attempt = 1, random = Math.random) {
    const base = retryAfter ?? Math.min(BUSY.maxMs, BUSY.firstMs * 2 ** Math.max(0, attempt - 1));
    const share = Math.min(1, Math.max(0, Number(random()) || 0));
    return Math.min(BUSY.maxMs, Math.round(base * (1 + BUSY.jitter * share)));
  }
  // The error of a busy answer: fixed words, the code 'BUSY', the status, and the wait it asked for (null if none).
  function busyError(status, retryAfter = null) {
    const error = new Error('BUSY: the service is busy; ask again later');
    error.code = 'BUSY'; error.busy = true; error.status = status; error.retryAfterMs = retryAfter; return error;
  }
  function isBusy(error) { return typeof error === 'object' && error !== null && error.busy === true && error.code === 'BUSY'; }
  // The busy error of an answer (a fetch Response), told by its status and its Retry-After header, or null. For the
  // requests a wallet makes itself, to other services.
  function busyAnswer(response) { return busyStatus(response?.status) ? busyError(response.status, retryAfterMs(response.headers?.get?.('Retry-After'))) : null; }
  // The version of a verified state, if this build implements it. A later version throws
  // UPGRADE_REQUIRED; a state that names no version this network can have is refused.
  function requireKnownVersion(state) {
    const version = state?.protocol_version;
    invariant(sinceFirstVersion(version), 'The verified state names no protocol version of this network');
    if (!knowsVersion(version)) throw upgradeRequired(version);
    return version;
  }
  // What a verified state says about a change of the protocol version: {version, scheduled, known}.
  // - version: the version in force.
  // - scheduled: the plan the validators have scheduled ({version, spec, activate_elapsed_micros,
  //   scheduled_elapsed_micros}, times in microseconds of chain time since genesis), or null.
  // - known: whether this build implements the scheduled version under the scheduled
  //   specification (true when nothing is scheduled).
  // The state must have been asked for with `include_upgrade: true`. A state without the proven
  // entry says nothing about upgrades, and that is an error here: it is never read as "no plan".
  function upgradeStatusOf(state) {
    invariant(state && typeof state === 'object', 'A verified state is required to read the upgrade status');
    const version = requireKnownVersion(state);
    invariant(Object.hasOwn(state, 'upgrade'), 'This state was verified without the upgrade entry; ask for it with include_upgrade');
    const row = state.upgrade;
    if (row === null) return { version, scheduled: null, known: true };
    invariant(row && typeof row === 'object' && !Array.isArray(row) && Array.isArray(row.signals) && Object.keys(row).every(key => key === 'plan' || key === 'signals'), 'Unsupported upgrade row');
    if (!Object.hasOwn(row, 'plan')) return { version, scheduled: null, known: true };
    const plan = row.plan;
    invariant(plan && typeof plan === 'object' && !Array.isArray(plan) && Object.keys(plan).sort().join(',') === 'activate_elapsed_micros,scheduled_elapsed_micros,spec,version', 'Unsupported upgrade plan');
    decimal(plan.activate_elapsed_micros); decimal(plan.scheduled_elapsed_micros); hexToBytes(plan.spec, 32);
    invariant(isVersion(plan.version) && BigInt(plan.version) === BigInt(version) + 1n, 'An upgrade plan names the version after the one in force');
    return { version, scheduled: { ...plan }, known: knowsPlan(plan) };
  }
  // Whether a network's nodes answer the question about scheduled upgrades (`include_upgrade` in a
  // state selection, nodes from time-node-v5 0.7.0 on). The statement is part of the network's
  // pinned trust data: `trust.nodes_report_upgrades: true` in the trust object that is installed
  // independently of any gateway, beside `app_version` and `chain_id`. It is never learned from a
  // gateway's words. A client of such a network asks the question with every verified read, from
  // the first one, so a gateway can never single the question out, hold it or refuse it: a read
  // without the proven entry fails as a whole. A trust object that does not say so (a network
  // from before this field, or one whose nodes are older) leaves the question to the caller.
  function nodesReportUpgrades(trust) {
    const said = trust?.nodes_report_upgrades;
    invariant(said === undefined || typeof said === 'boolean', 'trust.nodes_report_upgrades is true or false');
    return said === true;
  }
  // ---- Upgrade signals: what a validator's owner needs before it supports a plan or withdraws.
  // The rules are the engine's (v5/src/upgrade.rs; spec/protocol-4.md, section 6). Everything
  // here is computed from verified state. Nothing is taken from a gateway's words, and nothing
  // here knows which plan is the right one: a plan's version, specification hash and start time
  // come from the release announcement, entered by the owner.
  //
  // The times of each profile, in microseconds of chain time (`upgrade::Params::of`): the least
  // time from scheduling to start, the farthest start a signal may name, the least time between
  // two changes of one validator's signal, and the longest a plan may wait after its start time.
  const SIGNAL_RULES=Object.freeze({
    production:Object.freeze({noticeMicros:'1814400000000',farthestMicros:'10368000000000',intervalMicros:'600000000',lateMicros:'3600000000'}),
    laboratory:Object.freeze({noticeMicros:'120000000',farthestMicros:'3600000000',intervalMicros:'1000000',lateMicros:'60000000'}),
  });
  // A node admits a new plan only if its start lies this much further away than the notice
  // (`engine::ADMISSION_MARGIN_MICROS`): admission runs on the clock of the last block.
  const SIGNAL_ADMISSION_MARGIN_MICROS='30000000';
  // Support needed to schedule a plan, and to keep it in every block: numerator, denominator.
  const SIGNAL_SHARES=Object.freeze({schedule:Object.freeze(['4','5']),keep:Object.freeze(['3','4'])});
  const SIGNAL_MAX_ENTRIES=256;
  // The payload that supports a plan, and the payload that withdraws.
  function signalSupport({version,spec,activateElapsedMicros}){const payload={activate_elapsed_micros:activateElapsedMicros,spec,version};signalBytes(payload);return payload;}
  function signalWithdrawal(){return {};}
  function samePlan(a,b){return Boolean(a&&b)&&a.version===b.version&&a.spec===b.spec&&a.activate_elapsed_micros===b.activate_elapsed_micros;}
  function elapsedOf(state){
    const elapsed=BigInt(decimal(String(state?.time_micros)))-BigInt(decimal(String(state?.genesis?.genesis_time_micros)));
    invariant(elapsed>=0n,'The verified state is dated before the start of its network');return elapsed;
  }
  // One entry of the proven row `upgrade/state`, in the two forms the engine writes.
  function signalEntry(entry){
    invariant(entry&&typeof entry==='object'&&!Array.isArray(entry),'Unsupported upgrade signal entry');
    const keys=Object.keys(entry).sort().join(',');decimal(entry.owner);decimal(entry.changed_elapsed_micros);
    if(keys==='changed_elapsed_micros,owner')return {owner:entry.owner,changed_elapsed_micros:entry.changed_elapsed_micros,plan:null};
    invariant(keys==='activate_elapsed_micros,changed_elapsed_micros,owner,spec,version','Unsupported upgrade signal entry');
    decimal(entry.activate_elapsed_micros);decimal(entry.version);hexToBytes(entry.spec,32);
    return {owner:entry.owner,changed_elapsed_micros:entry.changed_elapsed_micros,plan:{version:entry.version,spec:entry.spec,activate_elapsed_micros:entry.activate_elapsed_micros}};
  }
  // What one verified state proves about the accounts and validator candidates it carries, as
  // far as a signal is concerned. A Map from owner id to:
  // - `candidate`: 'live', 'archived' or 'none', when the state was asked for the candidate row;
  // - `jailed`: true or false, with it;
  // - `stopped`: null when the owner account's signal counts, 'recovery' while a guardian
  //   recovery of the account has its approvals, 'frozen' while a secured account is frozen (a
  //   freeze still running, or a replacement of its keys waiting). Left out when the state does
  //   not prove it: an account without a key that holds both powers may have a security row,
  //   and its absence is proven only for an account that was asked for by id with
  //   `include_security` (`ids` names those).
  function signalFactsOf(state,ids=[]){
    invariant(state&&typeof state==='object','A verified state is required');
    // A freeze and a waiting replacement are counted on the clock of account security (securityNow), which on a
    // network whose waits survive a stop is not the chain's time.
    const facts=new Map(),now=BigInt(securityNow(state)),of=id=>{if(!facts.has(id))facts.set(id,{});return facts.get(id);};
    const candidates=state.candidates&&typeof state.candidates==='object'&&!Array.isArray(state.candidates)?state.candidates:{};
    for(const id of Object.keys(candidates)){const row=candidates[id],fact=of(decimal(id));fact.candidate=row===null?'none':row.archived===true?'archived':'live';fact.jailed=row!==null&&row.jailed===true;}
    for(const account of Array.isArray(state.accounts)?state.accounts:[]){
      const id=decimal(String(account.id)),devices=Array.isArray(account.devices)?account.devices:[];
      if((state.recovery_cases||[]).some(item=>item.target===id&&item.ready_elapsed_micros!==null&&item.ready_elapsed_micros!==undefined)){of(id).stopped='recovery';continue;}
      // A key that holds both powers: a protocol-4 account, which has no security row.
      if(devices.some(device=>device.can_manage&&device.can_spend)){Object.assign(of(id),{stopped:null,secured:false});continue;}
      if(!Array.isArray(state.security)||!ids.includes(id))continue;
      const row=state.security.find(item=>item.account===id);
      const frozen=Boolean(row)&&(now<BigInt(decimal(row.frozen_until_elapsed_micros))||Boolean(row.pending_root&&BigInt(decimal(row.pending_root.expires_elapsed_micros))>=now));
      Object.assign(of(id),{stopped:frozen?'frozen':null,secured:Boolean(row),frozenUntilElapsedMicros:row&&BigInt(row.frozen_until_elapsed_micros)>now?row.frozen_until_elapsed_micros:null});
    }
    return facts;
  }
  // The proven status of upgrade signals: {height, version, nextVersion, nowElapsedMicros,
  // genesisTimeMicros, profile, rules, feeMicros, hold, scheduled, entries, rosters, validators,
  // plans, complete, account, waits}.
  // - `waits`: {rule, stoppedMicros}, the rule of the waits and the total of the chain's stops at
  //   this state (waitsSurviveStops, stoppedMicros): what makes a moment of a security row, such as
  //   the end of a freeze (`account.frozenUntilElapsedMicros`), a date. Add the stops to it, and
  //   while `rule` is true and the moment has not come, say the date is the earliest
  //   (securityDeadline gives both from a state).
  // - The state must have been read with `include_upgrade` and `include_pos`.
  // - `hold`: a validator safety hold is on. Nothing is scheduled or activated while it lasts.
  // - `rosters`: the validator set in force and each set already announced, with their voting
  //   powers. A plan needs its share in every one of them: the lowest counts.
  // - `validators`: every validator of those sets with its power in the set in force (`power`,
  //   '0' if it is only in an announced one), its `signal` (null, {withdrawn:true,...} or the
  //   plan it names, with the time of its last change), whether it is `jailed` and whether its
  //   signal `counts` (true, false, or null where the facts given do not prove it).
  // - `plans`: each plan a validator of those sets names, the scheduled one first, with its
  //   supporters and its tally: per roster the supporting power and the total, the `lowest`
  //   share, and whether that share reaches the four fifths that schedule a plan (`schedule`)
  //   and the three quarters that keep it (`keep`). The comparison is the engine's:
  //   support x 5 >= total x 4, and support x 4 >= total x 3. A jailed validator is in neither
  //   sum; a signal whose owner account is frozen or in a recovery is in the total only.
  //   `exact` is false when the facts do not say whether a supporter's signal counts, or,
  //   during a safety hold, whether a validator of these sets is jailed. The sums are then a
  //   count the engine may not share, in either direction: an unread supporter is counted, so
  //   the share can be higher than the engine's; an unread jailed validator that does not
  //   support the plan stays in the total, so the share can be lower. `schedule` and `keep`
  //   are then null: neither is known, and neither may be stated as fact.
  // - `account` (when `account` names one, read with `ids` and `candidates` for it): whether it
  //   owns a validator candidate that is not archived (`ownsValidator`), its entry, the plan it
  //   supports, when it may change its signal again, why its signal does not count now
  //   (`stopped`), its balance and the keys that may sign a signal (those that may spend).
  // `facts` is a Map of signalFactsOf; by default the facts of this state for `account`.
  function signalStatusOf(state,{account,facts,complete=true}={}){
    const upgrade=upgradeStatusOf(state),now=elapsedOf(state),pos=state.pos;
    invariant(pos&&typeof pos==='object'&&Array.isArray(pos.active)&&Array.isArray(pos.scheduled)&&pos.scheduled.length<=8&&typeof pos.safety_hold==='boolean'&&Object.hasOwn(SIGNAL_RULES,pos.profile),'This state was verified without the staking summary; ask for it with include_pos');
    const set=list=>{invariant(Array.isArray(list)&&list.length<=100,'Unsupported validator set');return list.map(item=>({owner:decimal(String(item?.owner)),power:decimal(String(item?.power))}));};
    const rosters=[{effectiveHeight:null,validators:set(pos.active)},...pos.scheduled.map(item=>({effectiveHeight:decimal(String(item?.effective_height)),validators:set(item?.validators)}))];
    const entries=(state.upgrade?.signals||[]).map(signalEntry);
    invariant(entries.length<=SIGNAL_MAX_ENTRIES&&entries.every((entry,index)=>index===0||BigInt(entries[index-1].owner)<BigInt(entry.owner))&&entries.every(entry=>entry.plan===null||BigInt(entry.plan.version)===BigInt(upgrade.version)+1n),'Unsupported upgrade row');
    const entryOf=new Map(entries.map(entry=>[entry.owner,entry]));
    if(account!==undefined)account=decimal(String(account));
    facts??=signalFactsOf(state,account===undefined?[]:[account]);
    const hold=pos.safety_hold,rules={...SIGNAL_RULES[pos.profile],admissionMarginMicros:SIGNAL_ADMISSION_MARGIN_MICROS};
    // Whether a validator is left out of the count (jailed), and whether its signal counts.
    // Without a hold no validator of these sets is jailed (`pos::Summary::safety_hold`).
    const judge=owner=>{
      const fact=facts.get(owner)||{},jailed=fact.jailed??(hold?null:false);
      const counts=jailed===true||fact.candidate==='archived'||fact.candidate==='none'||fact.stopped?false:jailed===null||fact.stopped===undefined?null:true;
      return {jailed,counts,stopped:fact.stopped};
    };
    const owners=[...new Set(rosters.flatMap(roster=>roster.validators.map(item=>item.owner)))].sort((a,b)=>BigInt(a)<BigInt(b)?-1:1);
    const validators=owners.map(owner=>{
      const entry=entryOf.get(owner),judged=judge(owner),inForce=rosters[0].validators.find(item=>item.owner===owner);
      return {owner,power:inForce?inForce.power:'0',inForce:Boolean(inForce),signal:!entry?null:entry.plan?{version:entry.plan.version,spec:entry.plan.spec,activate_elapsed_micros:entry.plan.activate_elapsed_micros,changed_elapsed_micros:entry.changed_elapsed_micros}:{withdrawn:true,changed_elapsed_micros:entry.changed_elapsed_micros},jailed:judged.jailed,counts:entry?.plan?judged.counts:null,stopped:judged.stopped??null};
    });
    const tally=plan=>{
      let exact=true;const counted=rosters.map(roster=>{
        let support=0n,total=0n;
        for(const item of roster.validators){
          const judged=judge(item.owner);if(judged.jailed===true)continue;if(judged.jailed===null)exact=false;
          total+=BigInt(item.power);
          if(!samePlan(entryOf.get(item.owner)?.plan,plan)||judged.counts===false)continue;
          if(judged.counts===null)exact=false;
          support+=BigInt(item.power);
        }
        return {support,total};
      });
      const reaches=([numerator,denominator])=>counted.every(({support,total})=>total>0n&&support*BigInt(denominator)>=total*BigInt(numerator));
      const lowest=counted.reduce((low,next)=>next.total===0n||(low.total!==0n&&next.support*low.total<low.support*next.total)?next:low);
      const text=({support,total})=>({support:support.toString(),total:total.toString()});
      return {rosters:counted.map(text),lowest:text(lowest),schedule:exact?reaches(SIGNAL_SHARES.schedule):null,keep:exact?reaches(SIGNAL_SHARES.keep):null,exact};
    };
    const named=[];if(upgrade.scheduled)named.push({version:upgrade.scheduled.version,spec:upgrade.scheduled.spec,activate_elapsed_micros:upgrade.scheduled.activate_elapsed_micros});
    for(const owner of owners){const plan=entryOf.get(owner)?.plan;if(plan&&!named.some(known=>samePlan(known,plan)))named.push(plan);}
    const plans=named.map(plan=>({...plan,scheduled:samePlan(plan,upgrade.scheduled),known:knowsPlan(plan),supporters:owners.filter(owner=>samePlan(entryOf.get(owner)?.plan,plan)),tally:tally(plan)}));
    let own=null;
    if(account!==undefined){
      const row=(state.accounts||[]).find(item=>String(item.id)===account),fact=facts.get(account)||{};
      invariant(row&&fact.candidate!==undefined,'The state does not prove this account and its validator candidate; ask for it with ids and candidates');
      invariant(fact.stopped!==undefined,'The state does not prove whether this account is frozen; ask for it with include_security');
      const entry=entryOf.get(account)||null,interval=BigInt(rules.intervalMicros),from=entry?BigInt(entry.changed_elapsed_micros)+interval:null;
      const inForce=rosters[0].validators.find(item=>item.owner===account);
      own={id:account,name:row.name,ownsValidator:fact.candidate==='live',candidate:fact.candidate,jailed:fact.jailed===true,inRoster:owners.includes(account),power:inForce?inForce.power:'0',
        entry:entry?{...(entry.plan||{withdrawn:true}),changed_elapsed_micros:entry.changed_elapsed_micros}:null,supports:entry?.plan??null,
        mayChangeFromElapsedMicros:from===null?null:from.toString(),mayChangeNow:from===null?entries.length<SIGNAL_MAX_ENTRIES:now>=from,
        stopped:fact.stopped,frozenUntilElapsedMicros:fact.frozenUntilElapsedMicros??null,secured:fact.secured===true,
        signers:(row.devices||[]).filter(device=>device.can_spend).map(device=>device.public_key),balance:decimal(String(row.balance)),nonce:decimal(String(row.nonce)),authEpoch:decimal(String(row.auth_epoch))};
    }
    return {height:String(state.height),version:upgrade.version,nextVersion:(BigInt(upgrade.version)+1n).toString(),nowElapsedMicros:now.toString(),genesisTimeMicros:String(state.genesis.genesis_time_micros),profile:pos.profile,rules,feeMicros:networkFee(state),hold,scheduled:upgrade.scheduled,known:upgrade.known,entries:entries.length,
      rosters:rosters.map(roster=>({effectiveHeight:roster.effectiveHeight,validators:roster.validators.length,total:roster.validators.reduce((sum,item)=>sum+BigInt(item.power),0n).toString()})),validators,plans,complete,account:own,
      waits:{rule:waitsSurviveStops(state),stoppedMicros:stoppedMicros(state)}};
  }
  // Whether the engine would take a signal of the status' account now: its checks, in its order
  // (the ordinary ones of `engine.rs`, then `upgrade::signal`), judged on a status read from
  // proven state. `intent` is {withdraw:true}, or {version, spec, activateElapsedMicros} as the
  // release announcement gives them. Returns {ok:true, kind:'support'|'withdraw', payload, plan,
  // joins, tight} or {ok:false, refusal, ...}, with `refusal` one of:
  // - 'not_owner': the account owns no validator candidate that is not archived;
  // - 'recovery', 'frozen': the account cannot act now (a guardian recovery has its approvals;
  //   a secured account is frozen, and the fee would lower its balance);
  // - 'fee': the account holds less than the network fee;
  // - 'version': a plan names the version after the one in force (`current`, `next`);
  // - 'start_too_soon', 'start_too_far': a new plan starts from the notice (and the admission
  //   margin of a node) to the farthest start ahead (`earliestElapsedMicros`,
  //   `latestElapsedMicros`, as of this state); only the scheduled plan may be nearer;
  // - 'no_change': the validator already supports exactly that plan, or supports none;
  // - 'interval': its signal changed less than the interval ago (`fromElapsedMicros`);
  // - 'table_full': the row holds the most entries it can.
  // `joins` says that the plan is the scheduled one; `tight` that its start is less than ten
  // minutes inside the window, so a node may refuse it by the time it arrives.
  // What cannot be judged here: a node admits a support signal only for a version and
  // specification it implements itself (its own policy, not a rule), and a secured account's
  // daily limit must cover the fee (account-security.mjs, `allowance`).
  function judgeSignal(status,intent){
    const own=status?.account;invariant(own&&intent&&typeof intent==='object','A status read for the signalling account, and what to signal, are required');
    const now=BigInt(status.nowElapsedMicros),refuse=(refusal,more={})=>({ok:false,refusal,...more});
    if(own.stopped==='recovery')return refuse('recovery');
    if(!own.ownsValidator)return refuse('not_owner');
    const withdraw=intent.withdraw===true;invariant(withdraw?Object.keys(intent).length===1:intent.withdraw===undefined,'A signal either withdraws or names a plan');
    const payload=withdraw?signalWithdrawal():signalSupport(intent),plan=withdraw?null:{version:payload.version,spec:payload.spec,activate_elapsed_micros:payload.activate_elapsed_micros};
    let joins=false,tight=false;
    if(plan){
      if(plan.version!==status.nextVersion)return refuse('version',{current:status.version,next:status.nextVersion});
      joins=samePlan(plan,status.scheduled);
      const start=BigInt(plan.activate_elapsed_micros),earliest=now+BigInt(status.rules.noticeMicros)+BigInt(status.rules.admissionMarginMicros),latest=now+BigInt(status.rules.farthestMicros),window={earliestElapsedMicros:earliest.toString(),latestElapsedMicros:latest.toString()};
      if(!joins&&start<earliest)return refuse('start_too_soon',window);
      if(!joins&&start>latest)return refuse('start_too_far',window);
      tight=!joins&&start-earliest<600000000n;
    }
    if(plan?samePlan(own.supports,plan):own.supports===null)return refuse('no_change');
    if(own.entry&&!own.mayChangeNow)return refuse('interval',{fromElapsedMicros:own.mayChangeFromElapsedMicros});
    if(!own.entry&&status.entries>=SIGNAL_MAX_ENTRIES)return refuse('table_full');
    if(BigInt(own.balance)<BigInt(status.feeMicros))return refuse('fee');
    if(own.stopped==='frozen')return refuse('frozen');
    return {ok:true,kind:withdraw?'withdraw':'support',payload,plan,joins,tight};
  }
  // The fee every account action pays, in microseconds. Protocol 4 fixed it at 1000. A network can
  // set a lower one in its genesis (`fee_micros`, 1 to 999), which is then part of every verified
  // state of it; a network that keeps the protocol-4 fee leaves the field out.
  const PROTOCOL_FEE_MICROS = '1000';
  // Whether `value` is a fee a network can have: a canonical decimal string from 1 to 1000.
  function isFee(value) { return typeof value === 'string' && /^[1-9][0-9]{0,3}$/.test(value) && Number(value) <= 1000; }
  // The fee of a network, read from a verified state of it.
  function networkFee(state) {
    invariant(state && typeof state === 'object', 'A verified state is required to read the network fee');
    invariant(state.config && typeof state.config === 'object' && !Array.isArray(state.config), 'A verified state carries the network configuration the network fee is read from');
    const written = state.config.fee_micros;
    if (written === undefined) return PROTOCOL_FEE_MICROS;
    invariant(isFee(written) && written !== PROTOCOL_FEE_MICROS, 'Unsupported network fee setting');
    return written;
  }
  // Names that look alike. A network whose genesis says `distinct_names` refuses a new account name that looks
  // like a name that exists: two names look alike when they have the same skeleton (the engine's rule is in
  // v5/src/names.rs, the test vectors in spec/name-skeleton-vectors.json). The skeleton of a name, in this order:
  // every _ is removed; every 0 becomes o and every 1 becomes l; then, in one pass from left to right without
  // overlap, rn becomes m and vv becomes w. A name of underscores alone has the empty skeleton, and such a
  // network refuses it.
  // What the rule does not catch is left to a wallet's own warning: one changed letter, i for l, b1nance for
  // binance (its skeleton is blnance).
  function nameSkeleton(name) { invariant(typeof name === 'string' && /^[a-z0-9_]{2,15}$/.test(name), 'Name must contain 2–15 lowercase letters, numbers or underscores'); return name.replace(/_/g, '').replace(/0/g, 'o').replace(/1/g, 'l').replace(/w/g, 'vv').replace(/rn|vv/g, pair => pair === 'rn' ? 'm' : 'w'); }
  // Whether a network refuses names that look alike, read from a verified state of it. The setting is part of the
  // network's genesis and comes with every verified state; a network without the rule leaves the field out.
  function distinctNames(state) {
    invariant(state && typeof state === 'object', 'A verified state is required to read the rule for names');
    invariant(state.config && typeof state.config === 'object' && !Array.isArray(state.config), 'A verified state carries the network configuration the rule for names is read from');
    const written = state.config.distinct_names;
    invariant(written === undefined || written === true, 'Unsupported setting for names that look alike');
    return written === true;
  }
  // Waits that survive a stop. A network whose genesis says `waits_survive_stops` counts the waits and freezes of
  // account security on the active clock: the chain's time since genesis minus the total of all stops, where a stop
  // is the part of the gap between a block and its parent beyond five minutes (the engine's rule is in
  // v5/src/security.rs, "The clock of the waits"). On such a network every moment a security row stores is a moment
  // on that clock: `ready_elapsed_micros` of a waiting payment, of a raise of the limit and of a replacement,
  // `expires_elapsed_micros` of a waiting replacement, `frozen_until_elapsed_micros` and `allowance_elapsed_micros`.
  // Compared with the chain's time, or shown as a date as they stand, they come too early by the total of the stops.
  // What a key signs is not moved: the `expires_elapsed_micros` of a freeze, of approvals and of a registration stay
  // in the chain's time on every network.
  //
  // Whether a network has the rule, read from a verified state of it. The setting is part of the network's genesis
  // and comes with every verified state; a network without the rule leaves the field out.
  function waitsSurviveStops(state) {
    invariant(state && typeof state === 'object', 'A verified state is required to read the rule for waits');
    invariant(state.config && typeof state.config === 'object' && !Array.isArray(state.config), 'A verified state carries the network configuration the rule for waits is read from');
    const written = state.config.waits_survive_stops;
    invariant(written === undefined || written === true, 'Unsupported setting for waits that survive a stop');
    return written === true;
  }
  // The total of all stops so far, in microseconds, read from a verified state: the field `stopped_micros` of the
  // metadata row, which comes with every verified state. '0' on a network without the rule, which has no such field.
  // A state that has the field without the rule, or the rule without the field, is not one the engine writes.
  function stoppedMicros(state) {
    const rule = waitsSurviveStops(state), written = state.stopped_micros;
    invariant(rule ? typeof written === 'string' : written === undefined, 'The total of stops belongs to a network whose waits survive a stop, and to no other');
    if (!rule) return '0';
    decimal(written); invariant(BigInt(written) <= elapsedOf(state), 'The stops exceed the time of the chain');
    return written;
  }
  // The clock the account security rules read at a verified state, in microseconds: the chain's time since genesis
  // minus the total of stops (the chain's time itself on a network without the rule). This is the "now" to compare
  // the moments of a security row with, and the one account-security.mjs takes as `nowElapsedMicros` (`allowance`,
  // `frozen`, `signInRefusal`).
  function securityNow(state) { return (elapsedOf(state) - BigInt(stoppedMicros(state))).toString(); }
  // When a moment stored in a security row comes due, as a real time. `storedMicros` is `ready_elapsed_micros`,
  // `expires_elapsed_micros` of a waiting replacement, or `frozen_until_elapsed_micros`. Gives:
  // - `due`: whether it has come at this state;
  // - `remainingMicros`: how much longer the chain must run until it comes ('0' when it has);
  // - `elapsedMicros`: the chain's time since genesis at which it comes, or came at the earliest: the stored moment
  //   plus the stops so far;
  // - `timeMicros`: the same as a date, in microseconds since 1970 (the genesis time added);
  // - `earliest`: true on a network with the rule while the moment has not come. The date is then the earliest
  //   possible one: every further stop moves it by the length of the stop, less the five minutes of a stop that count.
  //   Show it as "not before". On a network without the rule the date is exact.
  function securityDeadline(state, storedMicros) {
    const stored = BigInt(decimal(String(storedMicros))), stopped = BigInt(stoppedMicros(state)), now = elapsedOf(state) - stopped;
    const due = stored <= now, at = stored + stopped;
    invariant(at <= MAX_U64, 'The moment lies beyond the time a chain can count');
    return { due, remainingMicros: (due ? 0n : stored - now).toString(), elapsedMicros: at.toString(), timeMicros: (at + BigInt(state.genesis.genesis_time_micros)).toString(), earliest: waitsSurviveStops(state) && !due };
  }
  // Accounts that are protected from their first block. A network whose genesis says `protected_registration`
  // takes a registration that carries the account's set of keys and its policy (kind 45, REGISTER_PROTECTED_KIND):
  // the reveal of a sponsored registration, which creates the account with its keys in their roles instead of one
  // key that can do everything (the engine's rule is in v5/src/security.rs). On any other network the action is
  // refused. Read from a verified state, like the settings above.
  //
  // Its name in KINDS is `register_protected`. The HTTP API gives that name (`kind_name`), and the explorer puts
  // the action into words like every kind KINDS names.
  const REGISTER_PROTECTED_KIND = 45;
  function protectedRegistration(state) {
    invariant(state && typeof state === 'object', 'A verified state is required to read the rule for registrations');
    invariant(state.config && typeof state.config === 'object' && !Array.isArray(state.config), 'A verified state carries the network configuration the rule for registrations is read from');
    const written = state.config.protected_registration;
    invariant(written === undefined || written === true, 'Unsupported setting for registrations that carry a set of keys');
    return written === true;
  }
  function hexToBytes(value, size) { invariant(typeof value === 'string' && /^(?:[0-9a-f]{2})*$/.test(value) && (size === undefined || value.length === size * 2), 'Invalid canonical hexadecimal value'); return Uint8Array.from(value.match(/../g) || [], item => parseInt(item, 16)); }
  function bytesToHex(value) { return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join(''); }
  function concat(...values) { const result = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0)); let at = 0; for (const value of values) { result.set(value, at); at += value.length; } return result; }
  function u64(value) { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(decimal(value))); return bytes; }
  function u32(value) { invariant(Number.isInteger(value) && value >= 0 && value <= 0xffffffff, 'Invalid u32'); const bytes = new Uint8Array(4); new DataView(bytes.buffer).setUint32(0, value); return bytes; }
  function orderReference({nonce,expiresElapsedMicros,randomHex=bytesToHex(crypto.getRandomValues(new Uint8Array(16)))}) {
    return bytesToHex(concat(u64(nonce),u64(expiresElapsedMicros),hexToBytes(randomHex,16)));
  }
  function decodeOrderReference(reference) {
    const bytes=hexToBytes(reference,32),view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
    return {nonce:view.getBigUint64(0).toString(),expiresElapsedMicros:view.getBigUint64(8).toString(),randomHex:reference.slice(32)};
  }
  function checkMerchantQuote(reference,nonce,state) {
    // The quote rule came with version 4 and holds in every later one. The version is the one of
    // the verified state passed in, never a gateway's report.
    invariant(sinceFirstVersion(state?.protocol_version),'Nonce-bound payment quotes require verified application version 4 or later');
    const quote=decodeOrderReference(reference),elapsed=BigInt(state.time_micros)-BigInt(state.genesis.genesis_time_micros);
    invariant(quote.nonce===decimal(nonce),'This payment quote reserved another nonce. Request a fresh order and approve it again.');
    invariant(BigInt(quote.expiresElapsedMicros)>=elapsed,'This payment quote expired. Request a fresh order.');
    invariant(BigInt(quote.expiresElapsedMicros)<=elapsed+86400000000n,'Payment quote expiry exceeds the protocol limit');
    return quote;
  }
  function base64(value) { let text = ''; for (const byte of value) text += String.fromCharCode(byte); return btoa(text); }
  function fromBase64(value) { invariant(typeof value === 'string' && value.length <= 68 * 1024 * 1024, 'Invalid base64 payload'); return Uint8Array.from(atob(value), byte => byte.charCodeAt(0)); }
  function sortedJSON(value,depth=0) {
    invariant(depth<=32,'Extension JSON nesting exceeds limit');
    if(value===null||typeof value==='boolean'||typeof value==='string')return value;
    if(typeof value==='number'){invariant(Number.isSafeInteger(value)&&value>=0,'Extension numbers must be nonnegative safe integers');return value;}
    if(Array.isArray(value)){invariant(value.length<=4096,'Extension array exceeds limit');return value.map(v=>sortedJSON(v,depth+1));}
    invariant(value&&typeof value==='object'&&Object.getPrototypeOf(value)===Object.prototype,'Invalid extension JSON value');
    const result={};for(const key of Object.keys(value).sort()){invariant(!['__proto__','constructor','prototype'].includes(key),'Reserved extension JSON key');result[key]=sortedJSON(value[key],depth+1);}return result;
  }
  const EXTENSIONS=new Set([17,18,19,20,21,24,40,41,42,44,45,60,61,62,70,71,72,73,74,75,76,77]);
  // Kind 80, a validator's upgrade signal (docs/design/upgrade-mechanism.md, section 3.1). Its
  // payload is one of exactly two byte strings, and anything else is refused here, before it is
  // signed and when it is read back:
  //   {"activate_elapsed_micros":"D","spec":"H","version":"D"}    support this plan
  //   {}                                                           withdraw
  // D is a decimal u64 without leading zeros, H is 64 lowercase hexadecimal characters; the keys
  // stand in this order, without spaces. The engine takes no other form (v5/src/upgrade.rs,
  // `decode_signal`). The bytes are written out here, not left to a JSON encoder.
  const SIGNAL_KIND=80,SIGNAL_FORM='A signal payload is a plan (activate_elapsed_micros, spec, version) or {}';
  function signalBytes(payload){
    invariant(payload&&typeof payload==='object'&&!Array.isArray(payload)&&Object.getPrototypeOf(payload)===Object.prototype,SIGNAL_FORM);
    const keys=Object.keys(payload);if(keys.length===0)return utf8.encode('{}');
    invariant(keys.length===3&&['activate_elapsed_micros','spec','version'].every(key=>Object.hasOwn(payload,key)),SIGNAL_FORM);
    invariant(typeof payload.spec==='string'&&/^[0-9a-f]{64}$/.test(payload.spec),'The specification hash of a signal is 64 lowercase hexadecimal characters');
    return utf8.encode(`{"activate_elapsed_micros":"${decimal(payload.activate_elapsed_micros)}","spec":"${payload.spec}","version":"${decimal(payload.version)}"}`);
  }
  function canonicalPayload(kind, payload) {
    if(kind===SIGNAL_KIND)return signalBytes(payload);
    if(EXTENSIONS.has(kind)){invariant(payload&&typeof payload==='object'&&!Array.isArray(payload),'Extension payload must be an object');const body=utf8.encode(JSON.stringify(sortedJSON(payload)));invariant(body.length<=512*1024,'Extension payload exceeds 512 KiB');return body;}

    const fields = FIELDS[kind]; invariant(fields && payload && typeof payload === 'object' && !Array.isArray(payload), 'Unknown action or invalid payload');
    invariant(Object.keys(payload).length === fields.length && fields.every(field => Object.hasOwn(payload, field)), 'Action payload has missing or unknown fields');
    const canonical = {};
    for (const field of fields) {
      const value = payload[field];
      if (DECIMALS.has(field)) decimal(value);
      else if (field.startsWith('can_') || field === 'accept') invariant(typeof value === 'boolean', 'Permissions/consent must be boolean');
      else if (field === 'guardians') { invariant(Array.isArray(value) && value.length <= 5, 'Invalid guardians'); value.forEach(decimal); invariant(value.every((item, index) => index === 0 || BigInt(value[index - 1]) < BigInt(item)), 'Guardians must be unique and sorted by account ID'); }
      else if (field === 'name') invariant(typeof value === 'string' && /^[a-z0-9_]{2,15}$/.test(value), 'Name must contain 2–15 lowercase letters, numbers or underscores');
      else hexToBytes(value, field === 'proof' ? 64 : 32);
      canonical[field] = value;
    }
    return utf8.encode(JSON.stringify(canonical));
  }
  function buildAction({ networkId, kind, from, nonce, authEpoch, publicKey, payload }) {
    kind = typeof kind === 'string' ? KINDS[kind] : kind;
    invariant(kind!==1,'V4 registration requires a funded sponsor action44');
    const body = canonicalPayload(kind, payload);
    return concat(utf8.encode('TCDEVNET-ACTION-V1\0'), hexToBytes(networkId, 32), Uint8Array.of(kind), u64(from), u64(nonce), u64(authEpoch), hexToBytes(publicKey, 32), u32(body.length), body);
  }
  function compactBitcoinReceipt(receipt){
    invariant(receipt&&receipt.network==='regtest','This candidate accepts REGTEST receipts only');
    const transaction_hex=receipt.transaction_hex??bytesToHex(Uint8Array.from(receipt.transaction||[])),merkle_proof_hex=receipt.merkle_proof_hex??bytesToHex(Uint8Array.from(receipt.merkle_proof||[]));
    hexToBytes(transaction_hex);hexToBytes(merkle_proof_hex);hexToBytes(receipt.block_hash,32);
    invariant(transaction_hex.length>0&&transaction_hex.length<=240*1024*2&&merkle_proof_hex.length>0&&merkle_proof_hex.length<=4096*2,'Bitcoin proof exceeds supported funding budget; do not broadcast this payment');
    invariant(Number.isSafeInteger(receipt.vout)&&receipt.vout>=0&&receipt.vout<=0xffffffff,'Invalid Bitcoin output index');
    const expected_sats=typeof receipt.expected_sats==='string'?receipt.expected_sats:(invariant(Number.isSafeInteger(receipt.expected_sats),'Unsafe Bitcoin amount'),String(receipt.expected_sats));decimal(expected_sats);invariant(BigInt(expected_sats)>0n&&BigInt(expected_sats)<=2100000000000000n,'Bitcoin amount outside supply');
    return {network:'regtest',block_hash:receipt.block_hash,transaction_hex,vout:receipt.vout,expected_sats,merkle_proof_hex};
  }
  function sponsorConsentBytes({networkId,sponsorAccount,publicKey,commitment,expiresElapsedMicros}){
    return concat(utf8.encode('TIME-REGISTER-SPONSOR-V1\0'),hexToBytes(networkId,32),u64(sponsorAccount),hexToBytes(publicKey,32),hexToBytes(commitment,32),u64(expiresElapsedMicros));
  }
  // The expiry, on the chain's time since genesis, of the sponsor's consent that registerProtected signs at a verified
  // state: five minutes ahead, or the longest the network allows (`config.registration.max_lifetime_micros`) less twenty
  // seconds if that is shorter, and never less than one minute. The chain takes a sponsor's action only before that
  // moment (registration/src/lib.rs, `commit`: `expires_elapsed_micros > now`), and the commitment it makes lasts until
  // the same moment, so a consent whose expiry the chain's time has passed can make no commitment, and no account.
  // SPONSOR_CONSENT_MAX_AHEAD_MICROS is the most a consent of this SDK is dated ahead of the state it was signed on.
  const SPONSOR_CONSENT_MAX_AHEAD_MICROS='300000000';
  function sponsorConsentExpiry(state){
    const longest=/^[1-9][0-9]*$/.test(String(state?.config?.registration?.max_lifetime_micros??''))?BigInt(state.config.registration.max_lifetime_micros):90000000n;
    let ahead=longest-20000000n;if(ahead>BigInt(SPONSOR_CONSENT_MAX_AHEAD_MICROS))ahead=BigInt(SPONSOR_CONSENT_MAX_AHEAD_MICROS);if(ahead<60000000n)ahead=60000000n;
    return (elapsedOf(state)+ahead).toString();
  }
  // ---- A registration that creates its account protected (kind 45, on a network with `protected_registration`).
  // The steps are those of any sponsored registration, with a set of keys in them:
  //   1. every key of the set signs registrationRoleBytes: it accepts its role on the account that this
  //      registration key is about to create (account-security.mjs, `acceptRegistrationRole`, signs it);
  //   2. `security` is {keys: [{public_key, role, proof}], policy}: what the adopting action (kind 70) takes;
  //   3. the registration key signs the sponsor's consent (sponsorConsentBytes) over protectedNameCommitment, and
  //      the sponsor pays for that commitment (kind 44), exactly as for any registration;
  //   4. one block later the registration key signs the registration itself (signProtectedRegistration).
  // The commitment names the set, so the name is taken with exactly these keys and this policy or not at all: a
  // registration with another set does not match it, and neither does the protocol-4 reveal (kind 2). Keep name,
  // salt and `security` until step 4, as a wallet keeps name and salt today. The registration key becomes the
  // account's identity key. It is a key of the account only if the set lists it, in one role, with its acceptance.
  const REGISTRATION_ROLES = Object.freeze({ signin: 0, spend: 1, recover: 2 });
  // What the holder of `publicKey` signs to accept `role` on the account that `registrationKey` creates.
  function registrationRoleBytes({ networkId, registrationKey, role, publicKey }) {
    invariant(Object.hasOwn(REGISTRATION_ROLES, role), 'Unknown role');
    return concat(utf8.encode('TCDEVNET-REGISTER-KEY-V1\0'), hexToBytes(networkId, 32), hexToBytes(registrationKey, 32), Uint8Array.of(REGISTRATION_ROLES[role]), hexToBytes(publicKey, 32));
  }
  // The set of keys and the policy of a registration, in the one form the engine accepts: keys sorted by public
  // key, each once, each with its role and its acceptance; a policy of four decimal strings. Refuses here what the
  // engine would refuse after the sponsor has paid: no spend key, a threshold below two or above the number of
  // recovery keys, more than eight keys, and, when a verified `state` of the network is given, waiting periods
  // below the network's minimum or above thirty days.
  function protectedSetup(security, state) {
    invariant(security && typeof security === 'object' && !Array.isArray(security) && Object.keys(security).sort().join(',') === 'keys,policy', 'A security setup is {keys, policy}');
    invariant(Array.isArray(security.keys) && security.keys.length >= 1 && security.keys.length <= 8, 'A set has one to eight keys');
    const keys = security.keys.map(entry => {
      invariant(entry && typeof entry === 'object' && !Array.isArray(entry) && Object.keys(entry).sort().join(',') === 'proof,public_key,role', 'A key of a new set is {public_key, role, proof}: every key carries its acceptance');
      invariant(Object.hasOwn(REGISTRATION_ROLES, entry.role), 'Unknown role'); hexToBytes(entry.public_key, 32); hexToBytes(entry.proof, 64);
      return { proof: entry.proof, public_key: entry.public_key, role: entry.role };
    }).sort((a, b) => (a.public_key < b.public_key ? -1 : a.public_key > b.public_key ? 1 : 0));
    invariant(keys.every((entry, index) => index === 0 || keys[index - 1].public_key !== entry.public_key), 'A key appears twice');
    const policy = security.policy;
    invariant(policy && typeof policy === 'object' && !Array.isArray(policy) && Object.keys(policy).sort().join(',') === 'daily_limit_micros,delay_seconds,freeze_seconds,threshold', 'A policy is {threshold, daily_limit_micros, delay_seconds, freeze_seconds}');
    for (const field of ['threshold', 'daily_limit_micros', 'delay_seconds', 'freeze_seconds']) decimal(policy[field]);
    const recover = BigInt(keys.filter(entry => entry.role === 'recover').length);
    invariant(keys.some(entry => entry.role === 'spend'), 'At least one spend key is required');
    invariant(BigInt(policy.threshold) >= 2n && BigInt(policy.threshold) <= recover, 'The threshold is at least two and at most the number of recovery keys');
    for (const field of ['delay_seconds', 'freeze_seconds']) {
      invariant(BigInt(policy[field]) <= 2592000n, 'Waiting periods are at most 30 days');
      if (state !== undefined) invariant(BigInt(policy[field]) * 1000000n >= BigInt(decimal(state.config.recovery_min_delay_micros)), 'Waiting periods are at least the minimum of the network');
    }
    return { keys, policy: { daily_limit_micros: policy.daily_limit_micros, delay_seconds: policy.delay_seconds, freeze_seconds: policy.freeze_seconds, threshold: policy.threshold } };
  }
  // The commitment a sponsor pays for when the registration will carry `security`: SHA-256 of the domain, the
  // network, the registration key, the name, a zero byte, the salt, and the SHA-256 of `security` as JSON with
  // sorted keys and no spaces (`security::registration_commitment` in the engine).
  async function protectedNameCommitment({ networkId, publicKey, name, salt, security }) {
    invariant(typeof name === 'string' && /^[a-z0-9_]{2,15}$/.test(name), 'Invalid name');
    const sha = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    const setup = await sha(utf8.encode(JSON.stringify(sortedJSON(protectedSetup(security)))));
    return bytesToHex(await sha(concat(utf8.encode('TCDEVNET-NAME-PROTECTED-V1\0'), hexToBytes(networkId, 32), hexToBytes(publicKey, 32), utf8.encode(name), Uint8Array.of(0), hexToBytes(salt, 32), setup)));
  }
  // The registration itself, signed by the registration key: an action without an account, like a reveal. Submit it
  // at least one block after the sponsor's action, before the commitment expires. It pays nothing.
  async function signProtectedRegistration({ networkId, publicKey, privateKey, name, salt, security }) {
    invariant(typeof name === 'string' && /^[a-z0-9_]{2,15}$/.test(name), 'Invalid name'); hexToBytes(salt, 32);
    return signAction({ networkId, kind: REGISTER_PROTECTED_KIND, from: MAX_U64.toString(), nonce: '0', authEpoch: '0', publicKey, payload: { name, salt, security: protectedSetup(security) } }, privateKey);
  }
  function bitcoinBidCommitment({networkId,accountId,epoch,policyRevision}){
    invariant(decimal(accountId)!==MAX_U64.toString(),'Reserved earning account');return concat(utf8.encode('TIMEBID1'),hexToBytes(networkId,32),u64(accountId),u64(epoch),u64(policyRevision));
  }
  function publicHeadersAction(networkId,headers){const body=buildAction({networkId,kind:40,from:MAX_U64.toString(),nonce:'0',authEpoch:'0',publicKey:'00'.repeat(32),payload:{headers}});return concat(body,new Uint8Array(64));}
  async function signAction(args, privateKey) { const body = buildAction(args); return concat(body, new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, body))); }
  async function transactionHash(tx) { return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', tx))).toUpperCase(); }
  function decodeAction(tx) {
    const domain = utf8.encode('TCDEVNET-ACTION-V1\0'); invariant(tx instanceof Uint8Array && tx.length >= domain.length + 32 + 1 + 24 + 32 + 4 + 64 && domain.every((value, index) => value === tx[index]), 'Invalid action envelope');
    const view = new DataView(tx.buffer, tx.byteOffset, tx.byteLength); let at = domain.length;
    const networkId = bytesToHex(tx.slice(at, at += 32)); const kind = tx[at++];
    const from = view.getBigUint64(at).toString(); at += 8; const nonce = view.getBigUint64(at).toString(); at += 8; const authEpoch = view.getBigUint64(at).toString(); at += 8;
    const publicKey = bytesToHex(tx.slice(at, at += 32)); const length = view.getUint32(at); at += 4;
    invariant(at + length + 64 === tx.length, 'Action length mismatch'); const raw = tx.slice(at, at + length); const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    invariant(bytesToHex(canonicalPayload(kind, payload)) === bytesToHex(raw), 'Noncanonical action payload');
    return { networkId, kind, from, nonce, authEpoch, publicKey, payload };
  }
  async function nameCommitment({ networkId, publicKey, name, salt }) { invariant(/^[a-z0-9_]{2,15}$/.test(name), 'Invalid name'); return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', concat(utf8.encode('TCDEVNET-NAME-V1\0'), hexToBytes(networkId, 32), hexToBytes(publicKey, 32), utf8.encode(name), Uint8Array.of(0), hexToBytes(salt, 32))))); }
  function deviceProofBytes({ networkId, accountId, authEpoch, publicKey, canManage, canSpend }) { invariant(typeof canManage === 'boolean' && typeof canSpend === 'boolean', 'Invalid device permissions'); return concat(utf8.encode('TCDEVNET-DEVICE-V1\0'), hexToBytes(networkId, 32), u64(accountId), u64(authEpoch), hexToBytes(publicKey, 32), Uint8Array.of(Number(canManage), Number(canSpend))); }
  function recoveryProofBytes({ networkId, target, auth_epoch, policy_version, recovery_id, new_public_key, expires_elapsed_micros }) { return concat(utf8.encode('TCDEVNET-RECOVERY-V1\0'), hexToBytes(networkId, 32), u64(target), u64(auth_epoch), u64(policy_version), hexToBytes(recovery_id, 32), hexToBytes(new_public_key, 32), u64(expires_elapsed_micros)); }
  function loginMessage(challenge, { account, publicKey }) {
    invariant(challenge && challenge.purpose === 'login', 'Only a login challenge can be signed');
    const origin = new URL(challenge.origin).origin; invariant(origin === challenge.origin, 'Login origin must be canonical');
    hexToBytes(challenge.networkId, 32); hexToBytes(publicKey, 32);
    invariant(typeof challenge.nonce === 'string' && /^[0-9a-f]{64}$/.test(challenge.nonce), 'Invalid login nonce');
    invariant(Number.isSafeInteger(challenge.issuedAt) && Number.isSafeInteger(challenge.expiresAt) && challenge.expiresAt > challenge.issuedAt && challenge.expiresAt - challenge.issuedAt <= 180000 && challenge.expiresAt > Date.now(), 'Expired or invalid login challenge');
    return { purpose: 'login', origin, networkId: challenge.networkId, accountId: decimal(String(account.id)), authEpoch: decimal(String(account.auth_epoch)), publicKey, nonce: challenge.nonce, issuedAt: challenge.issuedAt, expiresAt: challenge.expiresAt };
  }
  function loginBytes(message) { return concat(utf8.encode('TCDEVNET-LOGIN-V1\0'), utf8.encode(JSON.stringify(loginMessage(message, { account: { id: message.accountId, auth_epoch: message.authEpoch }, publicKey: message.publicKey })))); }
  async function signLogin(challenge, { account, publicKey, privateKey }) { const message = loginMessage(challenge, { account, publicKey }); return { message, signature: bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, loginBytes(message)))) }; }
  function sameOriginURL(value) { const url = new URL(value, root.location?.origin); invariant(url.origin === root.location?.origin, 'Gateway must use the wallet origin'); return url; }
  // `onBusy`: told of each busy answer ({kind, busy: true, retryInMs, answer: its status}), of each wait for one
  // ({kind, busy: true, retryInMs}), and of an answer after either ({kind, busy: false}); `kind` is the route.
  // `timing`: {now, sleep, random}, for tests.
  function createClient({ gateway = root.location?.origin, verifier, trust, checkpointStorage = !root.process?.versions?.node ? root.localStorage : undefined, fetcher = root.fetch?.bind(root), onBusy = null, timing = {} } = {}) {
    let network, light, lightPromise;
    let latestHeight = -1n;
    const base = new URL(gateway);
    const loopback = ['http:', 'https:'].includes(base.protocol) && ['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname);
    invariant(trust?.app_version==='4', 'V4 requires an independently installed application-4 trust manifest');
    // From the pinned trust data, never from the gateway: see nodesReportUpgrades.
    const reportsUpgrades=nodesReportUpgrades(trust);
    // The one place where this client's requests go out (the network, light blocks, proofs, receipts, submit, and
    // whatever a wallet asks through `request`). A busy answer (see BUSY) is waited for: no request of the same kind
    // (route) goes out before its wait is over, whoever sends it, so that a refused read does not multiply; a read (GET)
    // is sent again after the wait, at most `tries` times within `budgetMs`, and the same read asked again while it
    // waits joins it; anything else is sent again only when its caller says it is the same bytes (`again`).
    const clock = { now: () => Date.now(), sleep: ms => new Promise(resolve => setTimeout(resolve, ms)), random: Math.random, ...timing };
    const holds = new Map(), busyKinds = new Set(), lines = new Map();
    const tell = event => { try { onBusy?.(event); } catch { /* the hook's own trouble is not the request's */ } };
    async function request(path, options = {}, { budgetMs = BUSY.budgetMs, tries = BUSY.tries, again } = {}) {
      const url = new URL(path, base), method = String(options.method || 'GET').toUpperCase(), retry = again ?? method === 'GET';
      if (method !== 'GET' || options.signal) return paced(url, options, { budgetMs, tries, retry });
      const key = url.href, line = lines.get(key);
      if (line) return line.then(value => structuredClone(value));
      const fresh = paced(url, options, { budgetMs, tries, retry }).finally(() => { lines.delete(key); });
      lines.set(key, fresh); return fresh;
    }
    async function paced(url, options, { budgetMs, tries, retry }) {
      const kind = url.pathname, until = clock.now() + budgetMs;
      let own = null, status = 503, told = false;
      for (let attempt = 1; ; attempt++) {
        const hold = holds.get(kind) ?? 0, left = hold - clock.now();
        if (left > 0) {
          // Waiting for a wait another request of this kind was told: a share of jitter of its own on top.
          const pause = hold === own ? left : Math.min(BUSY.maxMs, left + Math.round(left * BUSY.jitter * Math.min(1, Math.max(0, Number(clock.random()) || 0))));
          if (clock.now() + pause > until) throw busyError(status, left);
          tell({ kind, busy: true, retryInMs: pause }); told = true;
          await clock.sleep(pause);
          if (options.signal?.aborted) throw options.signal.reason ?? Object.assign(new Error('Aborted'), { name: 'AbortError' });
        }
        try {
          const result = await ask(url, options);
          // An answer after a wait: the service takes requests of this kind again, so no later one waits for an older
          // wait, and the hook hears it.
          if (busyKinds.delete(kind) || told) { holds.delete(kind); tell({ kind, busy: false }); }
          return result;
        } catch (error) {
          if (!isBusy(error)) throw error;
          status = error.status;
          const delay = busyDelayMs(error.retryAfterMs, attempt, clock.random);
          own = Math.max(holds.get(kind) ?? 0, clock.now() + delay); holds.set(kind, own); busyKinds.add(kind);
          tell({ kind, busy: true, retryInMs: delay, answer: error.status }); told = true;
          if (!retry || attempt >= tries || clock.now() + delay > until) throw error;
        }
      }
    }
    async function ask(url, options) {
      const response = await fetcher(url, { cache: 'no-store', credentials: 'same-origin', redirect: 'error', ...options, headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(root.process?.versions?.node && options.method === 'POST' ? { Origin: base.origin } : {}), ...options.headers } });
      // A refusal for load, by its status alone: nothing of it is read.
      const busy = busyAnswer(response);
      if (busy) { try { await response.body?.cancel?.(); } catch { /* nothing to read */ } throw busy; }
      let text;
      if (response.body?.getReader) {
        const reader = response.body.getReader(), chunks = []; let size = 0;
        try {
          while (true) {
            const { done, value } = await reader.read(); if (done) break;
            size += value.byteLength; invariant(size <= 8 * 1024 * 1024, 'Gateway response exceeds compact client limit'); chunks.push(value);
          }
        } catch (error) { await reader.cancel().catch(() => {}); throw error; } finally { reader.releaseLock(); }
        const bytes = new Uint8Array(size); let at = 0; for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.byteLength; }
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } else { text = await response.text(); invariant(text.length <= 8 * 1024 * 1024, 'Gateway response exceeds compact client limit'); }
      const result = JSON.parse(text);
      // A gateway's words are not this client's findings: see gatewayRefusal.
      if (!response.ok || result.error) throw gatewayRefusal(result.error || `Gateway HTTP ${response.status}`);
      return result;
    }
    async function getNetwork() {
      if (!network) {
        const metadata = await request('/api/network');
        // A gateway may report a fee, but nothing here relies on its word: getNetwork() gives a
        // fee only once this client has verified a state of the network itself (see
        // getVerifiedState). A report that no network could have is still refused.
        invariant(metadata.protocolVersion==='4' && (metadata.feeMicros===undefined || isFee(metadata.feeMicros)),'Unsupported V4 metadata');
        invariant(metadata.networkId===trust.network_id&&metadata.chainId===trust.chain_id,'Gateway differs from independently installed network pin');
        const {feeMicros:_reported,...unverified}=metadata;
        network=unverified;
      }return network;
    }
    async function loadVerifier() {
      if (!verifier) {
        invariant(loopback, 'Remote gateway verifier code must never be loaded');
        verifier = root.process?.versions?.node ? await import('./proof-verifier.mjs') : await import(new URL('/sdk/proof-verifier.js', root.location.origin));
      }
      invariant(typeof verifier.verifyViewProof === 'function', 'Independent compact proof verifier unavailable'); return verifier;
    }
    async function loadLight(){
      if(!lightPromise)lightPromise=(async()=>{
        const module=await loadVerifier();
        const {createLightClient}=await import(root.process?.versions?.node?'./light-client.mjs':new URL('/sdk/light-client.mjs',root.location.origin));
        light=createLightClient({trust,verifier:module,storage:checkpointStorage,fetchBlock:height=>request('/api/light-block'+(height?'?height='+height:''))});
        return light;
      })();return lightPromise;
    }
    function selection(input={}){
      const arrays=['names','ids','public_keys','owners','candidates','epochs','blocks'],flags=['include_pos','include_bitcoin','include_policy','include_security','include_upgrade'];
      invariant(input&&typeof input==='object'&&!Array.isArray(input)&&Object.keys(input).every(k=>arrays.includes(k)||flags.includes(k)),'Invalid proof selection');
      const value={};for(const field of arrays){invariant(input[field]===undefined||Array.isArray(input[field]),'Proof selections must be arrays');value[field]=[...new Set(input[field]||[])];}
      for(const field of flags){invariant(input[field]===undefined||typeof input[field]==='boolean','Proof flags must be booleans');value[field]=input[field]||false;}
      if(!value.include_security)delete value.include_security;
      // On a network whose pinned trust data says that its nodes report upgrades, every read asks.
      if(reportsUpgrades)value.include_upgrade=true;
      // Like include_security, left out when false: a node that predates the flag refuses it.
      if(!value.include_upgrade)delete value.include_upgrade;
      invariant(value.names.length<=8&&value.ids.length<=8&&value.public_keys.length<=8&&value.names.length+value.ids.length+value.public_keys.length<=16&&value.owners.length<=16&&value.candidates.length<=16&&value.epochs.length<=8&&value.blocks.length<=16,'Proof selection exceeds budget');
      value.names.forEach(n=>invariant(typeof n==='string'&&/^[a-z0-9_]{2,15}$/.test(n),'Invalid name'));value.public_keys.forEach(k=>hexToBytes(k,32));for(const f of ['ids','owners','candidates','epochs','blocks'])value[f].forEach(decimal);value.blocks.forEach(h=>invariant(h!=='0','Canonical history heights start at one'));return value;
    }
    // options.timeoutMs: the longest the whole read may take (0, the default: no limit). When it
    // passes, the request is abandoned and the read fails with an error marked `timeout: true`.
    async function getVerifiedState(input={},options={}){
      const timeoutMs=options?.timeoutMs??0;invariant(Number.isSafeInteger(timeoutMs)&&timeoutMs>=0&&timeoutMs<=600000,'timeoutMs is a number of milliseconds from 0 to 600000');
      if(!timeoutMs)return readVerifiedState(input);
      const abort=typeof root.AbortController==='function'?new root.AbortController():null;
      return new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>{const error=new Error(`No verified answer within ${Math.ceil(timeoutMs/1000)} s`);error.timeout=true;reject(error);abort?.abort();},timeoutMs);
        readVerifiedState(input,abort?.signal).then(value=>{clearTimeout(timer);resolve(value);},error=>{clearTimeout(timer);reject(error);});
      });
    }
    async function readVerifiedState(input,signal){
      const query=selection(input),lc=await loadLight();await lc.ready();const metadata=await getNetwork(),module=await loadVerifier();
      let last;
      for(let attempt=0;attempt<4;attempt++)try{
        const proof=await request('/api/view-proof?query='+encodeURIComponent(JSON.stringify(query)),signal?{signal}:{});
        await lc.updateToBlock(proof.light_block);
        const result=await module.verifyViewProof(proof,lc.getTrust(),query);
        invariant(result?.verified===true&&result.state?.network_id===metadata.networkId&&result.completeAccountSet===false,'Compact state verification failed');
        // The version in force is the one of this verified state. The installed verifier already
        // refuses one it does not implement; this SDK implements KNOWN_VERSIONS and says the same.
        if(result.state.protocol_version!==undefined)requireKnownVersion(result.state);
        // Asked for, the upgrade entry is there (null when proven absent). A verifier that left
        // it out has proven nothing about it, and that is never read as "no plan".
        if(query.include_upgrade)invariant(Object.hasOwn(result.state,'upgrade'),'The verified state lacks the upgrade entry that was asked for');
        const height=BigInt(result.state.height);invariant(height>=latestHeight,'Chain proof rolled back');latestHeight=height;
        // The fee is a setting of the network's genesis and comes with every verified state. From
        // here on getNetwork() gives the verified setting, whatever the gateway reported.
        metadata.feeMicros=networkFee(result.state);
        return {...result,requested:query,height:String(result.state.height)};
      }catch(error){last=error;if(!/ROLLBACK|CHECKPOINT_MISMATCH|LIGHT_UPDATE_BUDGET/.test(error.message))throw error;}
      throw last;
    }
    // Whether the validators have scheduled a change of the protocol version, read from proven
    // state (the row `upgrade/state`, or the proof that it is absent): {version, scheduled, known}.
    // See upgradeStatusOf. Throws when the answer cannot be verified; it is never a guess. A
    // gateway that holds this one request cannot hold the caller: after `timeoutMs` (20 s unless
    // set; 0 for no limit) it fails with an error marked `timeout: true`.
    async function getUpgradeStatus({timeoutMs=20000}={}){const {state}=await getVerifiedState({include_upgrade:true},{timeoutMs});return upgradeStatusOf(state);}
    // The proven status of upgrade signals for the validator of account `accountId` (see
    // signalStatusOf), read with proofs through this client's own verifier.
    // - One read proves the version, the plan, the signals, the validator sets and the account.
    //   Without it there is no status: its failure is thrown.
    // - Whether another validator's signal counts depends on its owner account (frozen, or in a
    //   recovery) and, during a validator safety hold, on which validators are jailed. One proof
    //   holds eight accounts and sixteen candidates, so these facts are read in further proofs,
    //   each verified, a few blocks after the first: `heights` names the first and the last. The
    //   validator sets and the signals are those of the first.
    // - `complete: false` (asked for, or a further read failed, or more than `maxReads` of them
    //   would be needed, or `timeoutMs` ran out) leaves facts out. The status then says so, and a
    //   tally that depends on a missing fact says `exact: false` and neither `schedule` nor `keep`.
    async function getSignalStatus(accountId,{complete=true,timeoutMs=30000,maxReads=16}={}){
      const id=decimal(String(accountId));
      invariant(Number.isSafeInteger(timeoutMs)&&timeoutMs>=1000&&timeoutMs<=600000&&Number.isSafeInteger(maxReads)&&maxReads>=0&&maxReads<=64,'timeoutMs is from 1000 to 600000 and maxReads from 0 to 64');
      const until=Date.now()+timeoutMs,left=()=>Math.max(1,until-Date.now());
      const base=(await getVerifiedState({ids:[id],candidates:[id],include_pos:true,include_upgrade:true,include_security:true},{timeoutMs:left()})).state;
      const facts=signalFactsOf(base,[id]),first=signalStatusOf(base,{account:id,facts});
      let all=true,last=base.height;
      if(complete){
        const accounts=first.validators.filter(item=>item.signal&&!item.signal.withdrawn&&facts.get(item.owner)?.stopped===undefined).map(item=>item.owner);
        const candidates=first.hold?first.validators.filter(item=>item.jailed===null).map(item=>item.owner):[];
        for(let reads=0;accounts.length||candidates.length;reads++){
          if(reads>=maxReads||Date.now()>=until){all=false;break;}
          const ids=accounts.splice(0,8);let more;
          try{more=(await getVerifiedState({ids,candidates:candidates.splice(0,16),include_security:true},{timeoutMs:left()})).state;}catch(error){if(isUpgradeRequired(error))throw error;all=false;break;}
          for(const [owner,fact] of signalFactsOf(more,ids))facts.set(owner,{...facts.get(owner),...fact});
          last=more.height;
        }
      }
      return {...signalStatusOf(base,{account:id,facts,complete:complete&&all}),heights:{first:String(base.height),last:String(last)}};
    }
    async function account(nameOrId) {
      const value = String(nameOrId), isId = /^(0|[1-9][0-9]*)$/.test(value), name = value.replace(/^@/, '');
      const { state } = await getVerifiedState(isId ? { ids: [value] } : { names: [name] });
      return state.accounts.find(item => isId ? String(item.id) === value : item.name === name) || null;
    }
    async function resolveName(value) { return account('@' + String(value).replace(/^@/, '')); }
    async function checkReceipt(proof,hash,{allowFast=true}={}){
      const lc=await loadLight();await lc.ready();const metadata=await getNetwork(),module=await loadVerifier();let checked;
      if(proof.fast===true){
        invariant(allowFast,'A receipt anchored in canonical history is required here');
        // The transaction's own block is final. This wallet's light client verifies the
        // gateway's checkpoint block itself; the headers tie the transaction's block to it.
        invariant(proof.light_block&&Array.isArray(proof.headers)&&proof.tx&&typeof module.verifyFastReceipt==='function','Finalized-block receipt proof is incomplete');
        const checkpoint=await lc.updateToBlock(proof.light_block);
        checked=await module.verifyFastReceipt({tx:proof.tx,headers:proof.headers},{...lc.getTrust(),checkpoint});
      }else{
        invariant(proof.anchor?.light_block,'Fresh canonical receipt anchor is required');await lc.updateToBlock(proof.anchor.light_block);
        checked=await module.verifyReceipt(proof,lc.getTrust());
      }
      const receipt={...checked,hash:checked.hash||checked.txHash};
      invariant(receipt.verified===true&&receipt.hash.toUpperCase()===hash.toUpperCase()&&receipt.executionVerified===true,'Receipt verification failed');
      receipt.action=decodeAction(hexToBytes(receipt.rawHex));receipt.networkId=receipt.action.networkId;invariant(receipt.networkId===metadata.networkId,'Wrong receipt network');return receipt;
    }
    // What a gateway says about a receipt is not this client's finding (see gatewayRefusal). After
    // an activation a gateway of this client's own generation refuses every receipt, because its
    // verifier does not implement the new version, and its refusal arrives here as a gateway's
    // words. So when a receipt request fails, or a wait runs out, this client looks for itself:
    // one verified read of the current state, given `ownCheckMs` at most. If its own verifier, or
    // requireKnownVersion, refuses that state with UPGRADE_REQUIRED, that refusal is returned,
    // with the hash of the transaction whose outcome this software can no longer learn. Anything
    // else returns null and changes nothing: a read that fails, is held or does not verify leaves
    // the first error as it was. The words of the first error are never read: every failure
    // leads to the same question, and the code is still set only where it was (see the head).
    async function ownVersionFinding(hash,ownCheckMs){
      try{await getVerifiedState({},{timeoutMs:ownCheckMs});}catch(found){if(isUpgradeRequired(found)){found.hash=hash;return found;}}
      return null;
    }
    async function waitReceipt(hash, { timeoutMs = 45000, action, ownCheckMs = 10000 } = {}) {
      invariant(/^[a-f0-9]{64}$/i.test(hash), 'Invalid transaction hash'); const until = Date.now() + timeoutMs;
      invariant(Number.isSafeInteger(ownCheckMs)&&ownCheckMs>=1000&&ownCheckMs<=60000,'ownCheckMs is a number of milliseconds from 1000 to 60000');
      const lc=await loadLight();await lc.ready();
      // Ask for the one-block form only if the installed verifier can check it.
      const fast=typeof (await loadVerifier()).verifyFastReceipt==='function'?'&fast=1':'';
      while (Date.now() < until) {
        // The gateway answers as soon as the receipt exists (or after `wait`). It is told
        // this wallet's checkpoint height so that its proof ends at or above it.
        const started=Date.now(),trusted=lc.getCheckpoint()?.height,wait=Math.max(0,Math.min(5000,until-started));let again=false,proof;
        // A gateway that holds the request longer than it promised is treated as "pending".
        const limit=typeof root.AbortSignal?.timeout==='function'?{signal:root.AbortSignal.timeout(wait+8000)}:{};
        // A busy answer is "not yet": the next ask waits for the wait it was told, within this wait's own time.
        try{proof = await request('/api/receipt?hash=' + hash.toUpperCase()+'&wait='+wait+fast+(trusted?'&trusted='+trusted:''),limit,{budgetMs:Math.max(1000,until-started)});}
        catch(error){if(!isBusy(error)&&error?.name!=='TimeoutError'&&error?.name!=='AbortError')throw (await ownVersionFinding(hash,ownCheckMs))||error;proof={pending:true};}
        if (!proof.pending) {
          try{return await checkReceipt(proof,hash);}catch(error){if(!/ROLLBACK|CHECKPOINT_MISMATCH|canonical receipt block hash proof missing/.test(error.message))throw error;again=true;}
        }
        if (action?.kind === 4) {
          const { state } = await getVerifiedState({ ids: [action.from] }), sender = state.accounts.find(a => a.id === action.from);
          if (BigInt(state.auction_epoch) > BigInt(action.payload.epoch) && sender && BigInt(sender.nonce) < BigInt(action.nonce)) { const error = new Error('Test bid expired before inclusion. Review and bid in a fresh epoch.'); error.code = 'BID_EXPIRED'; error.hash = hash; throw error; }
        }
        // A gateway that waited has already used the time; one that answered at once is
        // polled gently, also after an answer this wallet could not use.
        if(Date.now()-started<400)await new Promise(resolve => setTimeout(resolve, again?250:600));
      }
      const found=await ownVersionFinding(hash,ownCheckMs);if(found)throw found;
      const error = new Error('Transaction pending; retain its signed bytes and hash. Do not send a replacement blindly.'); error.hash = hash; throw error;
    }
    // `busyBudgetMs`: how long the same bytes may be sent again after busy answers (BUSY.submitBudgetMs unless given;
    // a wallet gives BUSY.protectiveBudgetMs to an action that protects an account). They are never signed again: a
    // signed action is taken once, by its hash. A busy error that ends it carries the hash.
    async function submit(tx, { wait = true, busyBudgetMs = BUSY.submitBudgetMs } = {}) {
      invariant(Number.isSafeInteger(busyBudgetMs) && busyBudgetMs >= 1000 && busyBudgetMs <= 600000, 'busyBudgetMs is a number of milliseconds from 1000 to 600000');
      const hash = await transactionHash(tx);
      try {
        const metadata = await getNetwork(), action = decodeAction(tx); invariant(action.networkId === metadata.networkId, 'Wrong transaction network');
        const current=await getVerifiedState(action.from === MAX_U64.toString() ? { public_keys: [action.publicKey] } : { ids: [action.from] });
        // Decided from the state just verified (checkMerchantQuote reads its version), not from
        // the version the gateway reports, which is the network's first one for ever.
        if(action.kind===10)checkMerchantQuote(action.payload.reference,action.nonce,current.state);
        const result = await request('/api/submit', { method: 'POST', body: JSON.stringify({ tx: base64(tx) }) }, { again: true, budgetMs: busyBudgetMs, tries: BUSY.submitTries });
        invariant(result.hash?.toUpperCase() === hash, 'Gateway returned another transaction hash'); return wait ? await waitReceipt(hash, { action }) : { hash, pending: true };
      } catch (error) { if (isBusy(error)) error.hash = hash; throw error; }
    }
    async function perform({ kind, account: selected, publicKey, privateKey, payload }) {
      const { state } = await getVerifiedState({ ids: [String(selected.id)] }), current = state.accounts.find(a => a.id === String(selected.id));
      const code=typeof kind==='string'?KINDS[kind]:kind,device=current?.devices.find(d=>d.public_key===publicKey),managing=[8,9,11,12,13,14,16].includes(code);
      invariant(device&&(managing?device.can_manage:device.can_spend),'Device permission is insufficient');
      const elapsed=BigInt(state.time_micros)-BigInt(state.genesis.genesis_time_micros),frozen=(state.recovery_cases||[]).some(r=>r.target===current.id&&r.ready_elapsed_micros!==null&&BigInt(r.expires_elapsed_micros)>=elapsed);
      invariant(code===14||!frozen,'Guardian recovery freezes this account');
      // Checked at every version: the quote rule holds from version 4 on, and checkMerchantQuote
      // refuses a state of any earlier one.
      if(kind===10||kind==='merchant_payment')checkMerchantQuote(payload.reference,(BigInt(current.nonce)+1n).toString(),state);
      return submit(await signAction({ kind, from: current.id, nonce: (BigInt(current.nonce) + 1n).toString(), authEpoch: current.auth_epoch, networkId: state.network_id, publicKey, payload }, privateKey));
    }
    // ---- Signing up protected: a new account with its keys in their roles and its daily limit from its first
    // block (kind 45), its registration paid by a sponsor, at no cost to the newcomer. On a network whose genesis
    // has `protected_registration` (protectedRegistration of a verified state); on any other it throws, before
    // anything is signed or sent, an error with code 'PROTECTED_REGISTRATION_UNAVAILABLE', and a wallet registers
    // with the reveal (kind 2) as before.
    //
    //   sponsor       {account, ask(body)}: the account that pays, and how to ask it. `body` is {public_key,
    //                 commitment, expires_elapsed_micros, proof}; `ask` returns {hash}, the hash of the sponsor's
    //                 action (kind 44), or {alreadyCommitted: true}. A wallet's registrationSponsor() gives this
    //                 object, for the gateway's own sponsor and for a registration service (a test network's faucet).
    //                 It may be left out when the chain holds the account or this key's commitment already: no
    //                 sponsor is asked then. Left out when neither is there, the call throws code 'SPONSOR_REQUIRED'
    //                 before anything is signed: call again with a sponsor.
    //   onConsent     optional, called with {expiresElapsedMicros, publicKey, commitment} and awaited before the
    //                 registration key signs a sponsor's consent, which is before any sponsor is asked: the moment of
    //                 the chain's time (sponsorConsentExpiry) after which that consent can make no commitment, and with
    //                 it no account. A wallet keeps it to know when a sign-up whose commitment it does not see is void.
    //                 If it throws, nothing is signed or sent.
    //   name, salt    the account's name, and 32 random bytes in hexadecimal. Keep both until the account exists.
    //   registration  {publicKey, privateKey}: the registration key. It signs the sponsor's consent and the
    //                 registration, and becomes the account's identity key; it is a key of the account only if
    //                 `keys` lists it.
    //   keys          {signin, spend, recover}: lists of keys by role. A key is {publicKey, privateKey}, whose
    //                 acceptance of its role is signed here, or {publicKey, proof}: an acceptance signed elsewhere
    //                 (account-security.mjs, acceptRegistrationRole). Every acceptance is checked here.
    //   dailyLimitMicros, delaySeconds, freezeSeconds, and threshold ('2' unless given): the policy.
    //   waitMs        how long each wait for the chain may take (45 seconds unless given).
    //
    // Returns {account, security, receipt, sponsorReceipt} once a verified state shows the account with exactly
    // these keys in these roles and this policy: its account row and security row, the verified receipt of the
    // registration and that of the sponsor's action (null for what an earlier call already saw in a block).
    //
    // What the sponsor is given: the registration key's public key, the commitment, its expiry, and the registration
    // key's consent. Never a private key, the name, the salt or a key of the set: the commitment hides them.
    // Why it cannot put keys of its own on the account: the commitment is a hash of the name, the salt and the whole
    // set (protectedNameCommitment); the consent the registration key signs names that commitment, the sponsor and
    // the network (sponsorConsentBytes), and the chain takes a sponsor's action only with that consent; the chain
    // creates the account only from a registration that matches the commitment, signed by the registration key, in
    // a later block. A sponsor that names an action that pays for anything else is refused here, before the
    // registration is signed (code 'SPONSOR_MISMATCH'), and so is another commitment of this key on the chain
    // ('COMMITMENT_MISMATCH'). The checks are those of the sign-up with a reveal: the receipts are verified, and the
    // commitment and the account are read from verified states.
    //
    // Called again after an interruption it goes on from what the chain shows: a commitment that is there is not
    // paid for again, the registration is the same bytes (Ed25519 signs deterministically), and an account that
    // exists is checked and returned. A name that another key holds throws code 'NAME_TAKEN', an account of this
    // name and key with other keys or another policy 'REGISTRATION_MISMATCH'.
    async function registerProtected({sponsor=null,onConsent,name,salt,registration,keys,dailyLimitMicros,delaySeconds,freezeSeconds,threshold='2',waitMs=45000}={}){
      const refuse=(code,message)=>{const error=new Error(message);error.code=code;return error;},pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
      invariant(sponsor===null||(typeof sponsor==='object'&&typeof sponsor.ask==='function'&&/^(0|[1-9][0-9]{0,19})$/.test(String(sponsor.account??''))),'A sponsor is {account, ask(body)}');
      invariant(onConsent===undefined||typeof onConsent==='function','onConsent is a function');
      invariant(typeof name==='string'&&/^[a-z0-9_]{2,15}$/.test(name),'Invalid name');hexToBytes(salt,32);
      invariant(registration?.privateKey,'The registration key is {publicKey, privateKey}');hexToBytes(registration.publicKey,32);
      invariant(keys&&typeof keys==='object'&&!Array.isArray(keys)&&Object.keys(keys).every(role=>Object.hasOwn(REGISTRATION_ROLES,role)&&Array.isArray(keys[role])),'keys is {signin, spend, recover}, each a list of keys');
      invariant(Number.isSafeInteger(waitMs)&&waitMs>=1000&&waitMs<=600000,'waitMs is a number of milliseconds from 1000 to 600000');
      const reg=registration.publicKey,networkId=(await getNetwork()).networkId;
      // Each key's acceptance of its role for this registration key: signed here, or given and checked.
      const entries=[];
      for(const role of Object.keys(REGISTRATION_ROLES))for(const key of keys[role]??[]){
        invariant(key&&typeof key==='object','A key is {publicKey, privateKey} or {publicKey, proof}');hexToBytes(key.publicKey,32);
        const message=registrationRoleBytes({networkId,registrationKey:reg,role,publicKey:key.publicKey});
        const proof=key.privateKey?bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519',key.privateKey,message))):key.proof;hexToBytes(proof,64);
        const verifying=await crypto.subtle.importKey('raw',hexToBytes(key.publicKey,32),'Ed25519',false,['verify']);
        invariant(await crypto.subtle.verify('Ed25519',verifying,hexToBytes(proof,64),message),'The acceptance of a key does not verify: each key accepts its role for this network and this registration key');
        entries.push({public_key:key.publicKey,role,proof});
      }
      const policy={threshold:decimal(String(threshold)),daily_limit_micros:decimal(String(dailyLimitMicros)),delay_seconds:decimal(String(delaySeconds)),freeze_seconds:decimal(String(freezeSeconds))};
      const read=async selection=>(await getVerifiedState(selection,{timeoutMs:waitMs})).state,look=()=>read({names:[name],public_keys:[reg]});
      let state=await look();
      if(!protectedRegistration(state))throw refuse('PROTECTED_REGISTRATION_UNAVAILABLE','This network does not take a registration that carries a set of keys (its genesis has no protected_registration). Nothing was signed or sent: register with the reveal (kind 2).');
      const security=protectedSetup({keys:entries,policy},state);
      const commitment=await protectedNameCommitment({networkId,publicKey:reg,name,salt,security});
      // The account, read again with its security row: exactly these keys in these roles, and this policy.
      async function created(found,receipt,sponsorReceipt){
        if(found.public_key!==reg)throw refuse('NAME_TAKEN',`The name ${name} belongs to another account.`);
        const id=String(found.id),checked=await read({ids:[id],include_security:true});
        const account=checked.accounts.find(item=>String(item.id)===id),row=(checked.security||[]).find(item=>item.account===id)??null;
        const flags={signin:'false,false',spend:'false,true',recover:'true,false'};
        const want=security.keys.map(entry=>`${entry.public_key}:${flags[entry.role]}`).sort().join(' '),have=(account?.devices||[]).map(device=>`${device.public_key}:${device.can_manage},${device.can_spend}`).sort().join(' ');
        if(!row||want!==have||JSON.stringify(sortedJSON(row.policy))!==JSON.stringify(sortedJSON(security.policy)))throw refuse('REGISTRATION_MISMATCH',`The account ${name} does not have the keys and the policy of this registration.`);
        return {account,security:row,receipt,sponsorReceipt};
      }
      const named=()=>state.accounts.find(item=>item.name===name)??null;
      if(named())return created(named(),null,null);
      invariant(!state.accounts.some(item=>item.public_key===reg),'This registration key is the identity key of another account: use a new one');
      const commitOf=()=>(state.name_commits||[]).find(item=>item.public_key===reg)??null,another='Another registration of this key waits on the chain: its commitment names another name, salt or set of keys. Wait until it expires (a day at most), or use another registration key.';
      let commit=commitOf(),sponsorReceipt=null;
      if(commit&&commit.commitment!==commitment)throw refuse('COMMITMENT_MISMATCH',another);
      if(!commit){
        if(sponsor===null)throw refuse('SPONSOR_REQUIRED','Neither the account nor a commitment of this registration key is on the chain, so a sponsor must pay for one. Nothing was signed or sent: call again with a sponsor.');
        const sponsorAccount=String(sponsor.account);
        // The consent is good for five minutes, or the longest the network allows less twenty seconds, as for a reveal.
        const expires=sponsorConsentExpiry(state);
        if(onConsent)await onConsent({expiresElapsedMicros:expires,publicKey:reg,commitment});
        const proof=bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519',registration.privateKey,sponsorConsentBytes({networkId,sponsorAccount,publicKey:reg,commitment,expiresElapsedMicros:expires}))));
        const issued=await sponsor.ask({public_key:reg,commitment,expires_elapsed_micros:expires,proof});
        if(typeof issued?.hash==='string'){
          invariant(/^[0-9a-f]{64}$/i.test(issued.hash),'The sponsor answered with something that is not the hash of an action');
          sponsorReceipt=await waitReceipt(issued.hash,{timeoutMs:waitMs});
          const paid=sponsorReceipt.action;
          if(paid.kind!==KINDS.sponsor_registration||paid.from!==sponsorAccount||paid.payload.public_key!==reg||paid.payload.commitment!==commitment||paid.payload.expires_elapsed_micros!==expires)
            throw refuse('SPONSOR_MISMATCH','The sponsor named an action that does not pay for this registration. Nothing was registered, and the registration was not signed.');
        }else invariant(issued?.alreadyCommitted===true,'The sponsor named no action to wait for');
        // A receipt is verified a block ahead of the state read next: the state is asked again until it shows the commitment.
        for(const end=Date.now()+waitMs;;){state=await look();commit=commitOf();if(commit||Date.now()>end)break;await pause(400);}
        invariant(commit,'The sponsored commitment is not in a verified state yet: call again in a moment, with the same name, salt and keys');
        if(commit.commitment!==commitment)throw refuse('COMMITMENT_MISMATCH',another);
      }
      // The registration goes into a later block than the commitment.
      for(const end=Date.now()+waitMs;BigInt(state.height)<=BigInt(commit.height)&&Date.now()<end;){await pause(500);state=await look();}
      invariant(BigInt(state.height)>BigInt(commit.height),'Waiting for the block after the commitment: call again in a moment, with the same name, salt and keys');
      const tx=await signProtectedRegistration({networkId,publicKey:reg,privateKey:registration.privateKey,name,salt,security});
      let receipt;
      try{receipt=await submit(tx,{wait:false});receipt=await waitReceipt(receipt.hash,{timeoutMs:waitMs});}catch(error){
        // The same bytes may have reached the node before (an earlier call that stopped): their receipt settles it.
        if(isUpgradeRequired(error))throw error;
        try{receipt=await waitReceipt(await transactionHash(tx),{timeoutMs:Math.min(15000,waitMs)});}catch{throw error;}
      }
      let found=null;
      for(const end=Date.now()+waitMs;;){state=await read({names:[name]});found=named();if(found||Date.now()>end)break;await pause(400);}
      invariant(found,'The registration is in a block, and the account is not in a verified state yet: call again in a moment, with the same name, salt and keys');
      return created(found,receipt,sponsorReceipt);
    }
    async function exportReceiptEvidence(hash){
      invariant(/^[a-f0-9]{64}$/i.test(hash),'Invalid transaction hash');let proof;try{proof=await request('/api/receipt?hash='+hash.toUpperCase()+'&canonical=1');}catch(error){throw (await ownVersionFinding(hash,10000))||error;}invariant(!proof.pending,'Awaiting canonical receipt anchor');await checkReceipt(proof,hash,{allowFast:false});
      return {format:'timecurrency-public-receipt',version:4,verifiedAtMs:Date.now(),trust:(await loadLight()).getTrust(),proof,notice:'Checkpoint must be independently authenticated; a file or RPC cannot grant its own trust. Reanchor retained evidence after seven days using a currently trusted client.'};
    }
    async function getBitcoinBidQuote({accountId,epoch,sats}){
      decimal(accountId);decimal(epoch);decimal(sats);const {state}=await getVerifiedState({ids:[accountId],include_bitcoin:true,include_policy:true});
      invariant(state.accounts.some(a=>a.id===accountId),'Earning account is absent');invariant(!state.treasury.paused,'Treasury receiving is paused');invariant(!state.treasury.pending,'Treasury rotation is pending; request a funding quote after policy activation or cancellation');
      invariant(state.config.all_new_time_to_validators!==true,'This network has no bitcoin auction: new seconds go to validators and the people who stake with them');
      const config=state.config.auction,current=(BigInt(state.time_micros)-BigInt(state.genesis.genesis_time_micros))/(BigInt(config.epoch_seconds)*1000000n);
      invariant(BigInt(epoch)>=current+BigInt(config.bid_lead_epochs)&&BigInt(epoch)<=current+BigInt(config.max_future_epochs),'Earning epoch outside fresh allowed window');
      invariant(BigInt(sats)>=BigInt(config.min_sats)&&BigInt(sats)<=BigInt(config.max_sats),'Bitcoin amount outside policy bounds');
      invariant(state.config.bitcoin.network==='regtest','This candidate accepts Bitcoin REGTEST only');
      const policy=state.receiving_policy;invariant(Number.isSafeInteger(policy.revision)&&policy.revision>0,'Unsupported receiving revision');
      const commitment=bitcoinBidCommitment({networkId:state.network_id,accountId,epoch,policyRevision:String(policy.revision)});
      return {network:'regtest',networkId:state.network_id,accountId,epoch,policyRevision:String(policy.revision),sats,receivingScriptHex:bytesToHex(Uint8Array.from(policy.script_pubkey)),opReturnScriptHex:'6a40'+bytesToHex(commitment),commitmentHex:bytesToHex(commitment),stateHeight:state.height,notice:'REGTEST only. A Bitcoin wallet must create both exact outputs; no refund or fixed earning amount is promised.'};
    }
    async function importTrustedCheckpoint(checkpoint,independentHash){return (await loadLight()).importTrustedCheckpoint(checkpoint,independentHash);}
    return Object.freeze({nodesReportUpgrades:reportsUpgrades,getNetwork,getVerifiedState,getUpgradeStatus,getSignalStatus,account,resolveName,submit,waitReceipt,perform,registerProtected,exportReceiptEvidence,getBitcoinBidQuote,importTrustedCheckpoint,request});
  }
  function requestWallet({ walletOrigin, request, timeoutMs = 180000 }) {
    const prepared = Promise.resolve(request); prepared.catch(() => {});
    const target = new URL(walletOrigin); invariant(target.origin === walletOrigin && ['http:', 'https:'].includes(target.protocol), 'Invalid wallet origin');
    const id = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const popup = root.open(walletOrigin + '/approve', 'time-wallet-' + id, 'popup,width=460,height=780');
    invariant(popup, 'Allow the wallet popup to continue');
    return new Promise((resolve, reject) => {
      const finish = (error, result) => { settled = true; clearTimeout(timer); clearInterval(closed); root.removeEventListener('message', handler); error ? reject(error) : resolve(result); };
      let ready = false; let resolvedRequest; let settled = false; let sent = false;
      const send = () => { if (ready && resolvedRequest && !settled && !sent) { sent = true; popup.postMessage({ type: 'time:request', version: 1, id, request: resolvedRequest }, walletOrigin); } };
      const handler = event => { if (event.origin !== walletOrigin || event.source !== popup || settled) return; const data = event.data; if (data?.type === 'time:ready' && data.version === 1) { ready = true; send(); } if (data?.type === 'time:response' && data.version === 1 && data.id === id) { settled = true; finish(data.error ? new Error(data.error.message || 'Wallet request rejected') : null, data.result); } };
      root.addEventListener('message', handler); const timer = setTimeout(() => finish(new Error('Wallet approval expired')), timeoutMs); const closed = setInterval(() => { if (popup.closed) finish(new Error('Wallet window closed')); }, 400);
      prepared.then(value => { invariant(value && ['login', 'payment'].includes(value.type), 'Unsupported wallet request'); resolvedRequest = value; send(); }, error => { settled = true; finish(error); }).catch(error => { settled = true; finish(error); });
    });
  }
  root.TimeSDK = Object.freeze({ KINDS, MAX_U64: MAX_U64.toString(), BUSY, isBusy, busyAnswer, busyDelayMs, retryAfterMs, createClient, buildAction, signAction, transactionHash, decodeAction, canonicalPayload, nameCommitment, deviceProofBytes, recoveryProofBytes, loginMessage, loginBytes, signLogin, requestWallet, compactBitcoinReceipt, sponsorConsentBytes, sponsorConsentExpiry, SPONSOR_CONSENT_MAX_AHEAD_MICROS, bitcoinBidCommitment, publicHeadersAction, orderReference,decodeOrderReference,checkMerchantQuote,decimal, PROTOCOL_FEE_MICROS, isFee, networkFee, nameSkeleton, distinctNames, waitsSurviveStops, stoppedMicros, securityNow, securityDeadline, protectedRegistration, REGISTER_PROTECTED_KIND, registrationRoleBytes, protectedSetup, protectedNameCommitment, signProtectedRegistration, FIRST_VERSION, IMPLEMENTED, KNOWN_VERSIONS, sinceFirstVersion, knowsVersion, knowsPlan, requireKnownVersion, isUpgradeRequired, upgradeStatusOf, nodesReportUpgrades, SIGNAL_RULES, SIGNAL_ADMISSION_MARGIN_MICROS, SIGNAL_SHARES, signalSupport, signalWithdrawal, samePlan, signalFactsOf, signalStatusOf, judgeSignal, hexToBytes, bytesToHex, base64, fromBase64, concat, sameOriginURL });
})(globalThis);
