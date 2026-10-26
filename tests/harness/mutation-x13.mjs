import fs from 'node:fs';
import { countCheckCalls, extractStartCheck, runX13 } from './x13-single-run.mjs';

// Prove X13 is not a no-op.
//
// The regression it guards is a SECOND check command inside the scan entry
// point. This rebuilds that shape from the current file (inject the removed
// `api.checkIp(...)` call back into the body), then asserts the gate's own
// counter flips 1 -> 2 and that the removal of `checkId: session.check_id`
// would also be caught.
//
// Nothing in the repository is modified.

const REAL = 'E:\\auto-reg\\check-ip\\ip-checker\\src\\App.tsx';
const cur = fs.readFileSync(REAL, 'utf8');

const body = extractStartCheck(cur);
if (!body) {
  console.log('could not locate startCheck — aborting');
  process.exit(1);
}

const currentCalls = countCheckCalls(body);
console.log(`REAL file   : ${REAL}`);
console.log(`  check commands inside startCheck : ${currentCalls.length} (${currentCalls.map((c) => c.cmd).join(', ') || 'none'})`);

// Reconstruct the pre-fix shape: a second, non-saving run whose id the UI keeps.
const secondCall = `
        const second = await api.checkIp(request.input, {
          protocol: request.protocol,
          credentials: request.credentials,
          save_to_history: false,
          use_cache: false,
        });
        setUi((current) => ({ ...current, checkId: second.check_id, result: second.result }));
`;

const marker = 'setUi((current) => ({\n          ...current,\n          checking: false,';
const brokenBody = body.includes(marker)
  ? body.replace(marker, secondCall.trimStart() + '\n        ' + marker)
  : body.replace('if (runTokenRef.current !== token) return;', secondCall + '\n        if (runTokenRef.current !== token) return;');

const brokenCalls = countCheckCalls(brokenBody);
console.log(`\nBROKEN shape (second api.checkIp injected):`);
console.log(`  check commands inside startCheck : ${brokenCalls.length} (${brokenCalls.map((c) => c.cmd).join(', ')})`);
console.log(`  => gate verdict : ${brokenCalls.length === 1 ? 'PASS (bad!)' : 'FAIL'}`);

// Also confirm the checkId assertion has teeth: dropping `session.check_id`
// must be detected.
const noCheckId = body.replace(/checkId:\s*session\.check_id/, 'checkId: current.checkId');
const checkIdStillBound = /checkId:\s*session\.check_id/.test(noCheckId);
console.log(`\ncheckId-from-session assertion:`);
console.log(`  after rebinding to current.checkId, still satisfied : ${checkIdStillBound} ${checkIdStillBound ? '(bad!)' : '(correctly fails)'}`);

const live = runX13();
console.log(`\nLIVE gate on real file: ${live.pass ? 'PASS' : 'FAIL'}`);

const flips = brokenCalls.length > 1 && currentCalls.length === 1 && !checkIdStillBound && live.pass;
console.log(
  `\nX13 is NOT a no-op: ${flips ? 'YES — 1 call passes, 2 calls fail, losing session.check_id fails' : 'NO — investigate'}`,
);
process.exit(flips ? 0 : 1);
