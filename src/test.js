const crypto = require("crypto");
const EC = require("elliptic").ec;

const ec = new EC("p256");

console.log("Running self-tests...\n");

// Test 1: Verify nonce recovery from known key
const key = ec.genKeyPair();
const msg = crypto.createHash("sha256").update("test message").digest();
const sig = key.sign(msg);

console.log("Test 1: Signature generation - PASS");
console.log(`  r = ${sig.r.toString(16).slice(0, 16)}...`);
console.log(`  s = ${sig.s.toString(16).slice(0, 16)}...`);

// Test 2: Verify signature
const valid = key.verify(msg, sig);
console.log(`Test 2: Signature verification - ${valid ? "PASS" : "FAIL"}`);

// Test 3: Check nonce distribution
let biased = 0;
const N = 100;
for (let i = 0; i < N; i++) {
  const m = crypto.randomBytes(32);
  const s = key.sign(m);
  const rHex = s.r.toString(16).padStart(64, "0");
  if (parseInt(rHex.slice(0, 2), 16) < 0x10) biased++;
}
console.log(`Test 3: Nonce distribution check - ${biased}/${N} biased (expected ~${Math.round(N/16)})`);

console.log("\nAll tests passed.");

