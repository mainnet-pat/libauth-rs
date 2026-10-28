// Benchmark libauth's hashing and secp256k1 operations on the fixed inputs of
// `cargo run --release --bin crypto-bench`.
// Usage: node tools/bench-crypto.mjs [seconds per operation]
import { hexToBin, secp256k1, sha256 } from '/Code/libauth/build/index.js';

const seconds = Number(process.argv[2] ?? 2);

// Print the median time per call of `operation` over five timed rounds, after
// a warm-up.
const timePerOperation = (label, operation) => {
  for (let index = 0; index < 200; index += 1) operation();
  const rounds = [];
  for (let round = 0; round < 5; round += 1) {
    let count = 0;
    const start = process.hrtime.bigint();
    while (Number(process.hrtime.bigint() - start) / 1e9 < seconds / 5) {
      operation();
      count += 1;
    }
    rounds.push(Number(process.hrtime.bigint() - start) / 1e3 / count);
  }
  rounds.sort((a, b) => a - b);
  console.log(`${label}\t${rounds[2].toFixed(2)}`);
};

const key = hexToBin('f85d4bd8a03ca106c9deb47b791803dac7f0333809e3f1dd04d182e0aba6e553');
const message = hexToBin('da1e22c5f5f5f3f5d9a8b1c4e6f40f1b6c5b8a2f2a8c1e3d4b5a69788796a5b4');
const publicKey = secp256k1.derivePublicKeyCompressed(key);
const der = secp256k1.signMessageHashDER(key, message);
const schnorr = secp256k1.signMessageHashSchnorr(key, message);
const input520 = new Uint8Array(520).fill(0xab);
const input32 = new Uint8Array(32).fill(0xab);
// The last result is kept so the operations are not optimized away.
let result;
console.log('operation\tmedian µs');
timePerOperation('sha256 (520 bytes)', () => { result = sha256.hash(input520); });
timePerOperation('sha256 (32 bytes)', () => { result = sha256.hash(input32); });
timePerOperation('derive public key', () => { result = secp256k1.derivePublicKeyCompressed(key); });
timePerOperation('ECDSA sign (DER)', () => { result = secp256k1.signMessageHashDER(key, message); });
timePerOperation('ECDSA verify (DER)', () => {
  if (!secp256k1.verifySignatureDERLowS(der, publicKey, message)) throw new Error('verification failed');
});
timePerOperation('Schnorr sign', () => { result = secp256k1.signMessageHashSchnorr(key, message); });
timePerOperation('Schnorr verify', () => {
  if (!secp256k1.verifySignatureSchnorr(schnorr, publicKey, message)) throw new Error('verification failed');
});
if (result === undefined) throw new Error('no result');
