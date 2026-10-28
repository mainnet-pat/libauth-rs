// Benchmark the reference libauth VM on the shared near-limit program produced
// by `cargo run --release --bin vm-bench -- --write ...`.
import fs from 'node:fs';
import {
  createVirtualMachineBch2026,
  decodeTransaction,
  decodeTransactionOutputs,
  hexToBin,
} from '/Code/libauth/build/index.js';

const cpuMode = process.argv.includes('--cpu');
// `--cpu` may appear anywhere, so it is not a positional argument.
const positional = process.argv.slice(2).filter((argument) => argument !== '--cpu');
const fixturePath =
  positional[0] ?? '/Code/libauth-rs/tests/fixtures/vm_benchmark_program.json';
const iterations = Number(positional[1] ?? 200);
const warmup = Number(positional[2] ?? 20);
const samplesPath = positional[3];

const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const transaction = decodeTransaction(hexToBin(fixture.transaction));
const sourceOutputs = decodeTransactionOutputs(hexToBin(fixture.sourceOutputs));
if (typeof transaction === 'string') throw new Error(transaction);
if (typeof sourceOutputs === 'string') throw new Error(sourceOutputs);
const program = { inputIndex: fixture.inputIndex, sourceOutputs, transaction };

const vm = createVirtualMachineBch2026(false);
const initial = vm.evaluate(program);
const metrics = initial.metrics;
console.log(
  `success=${vm.stateSuccess(initial) === true} error=${initial.error ?? 'none'} stack_len=${initial.stack.length}`,
);
console.log(
  `  locking_len=${program.sourceOutputs[0].lockingBytecode.length} unlocking_len=${transaction.inputs[0].unlockingBytecode.length} density=${metrics.densityControlLength}`,
);
console.log(
  `  operation_cost=${metrics.operationCost} / ${metrics.maximumOperationCost} (${(
    (100 * metrics.operationCost) /
    metrics.maximumOperationCost
  ).toFixed(1)}%)`,
);
console.log(
  `  hash_iters=${metrics.hashDigestIterations} / ${metrics.maximumHashDigestIterations} (${(
    (100 * metrics.hashDigestIterations) /
    metrics.maximumHashDigestIterations
  ).toFixed(1)}%)`,
);
console.log(
  `  sigchecks=${metrics.signatureCheckCount} / ${metrics.maximumSignatureCheckCount} evaluated_instructions=${metrics.evaluatedInstructionCount}`,
);
console.log(
  `  stack_pushed_bytes=${metrics.stackPushedBytes} arithmetic_cost=${metrics.arithmeticCost}`,
);
if (vm.stateSuccess(initial) !== true) process.exit(1);

for (let index = 0; index < warmup; index += 1) vm.evaluate(program);

const samples = [];
for (let index = 0; index < iterations; index += 1) {
  const wallStart = process.hrtime.bigint();
  const cpuStart = process.cpuUsage();
  const state = vm.evaluate(program);
  const cpu = process.cpuUsage(cpuStart);
  const elapsed = cpuMode
    ? cpu.user + cpu.system
    : Number(process.hrtime.bigint() - wallStart) / 1000;
  if (vm.stateSuccess(state) !== true) throw new Error('evaluation failed');
  samples.push(elapsed);
}

if (samplesPath !== undefined) {
  fs.writeFileSync(samplesPath, `${samples.join('\n')}\n`);
}
samples.sort((a, b) => a - b);
const n = samples.length;
const mean = samples.reduce((total, value) => total + value, 0) / n;
const variance =
  samples.reduce((total, value) => total + (value - mean) ** 2, 0) / (n - 1);
const stddev = Math.sqrt(variance);
const median =
  n % 2 === 0 ? (samples[n / 2 - 1] + samples[n / 2]) / 2 : samples[(n - 1) / 2];
const ci95 = (1.96 * stddev) / Math.sqrt(n);
const percentile = (fraction) =>
  samples[Math.round((n - 1) * fraction)].toFixed(1);
console.log(
  `typescript iterations=${iterations} mean_us=${mean.toFixed(1)} median_us=${median.toFixed(1)} stddev_us=${stddev.toFixed(1)} ci95_us=${ci95.toFixed(1)} p90_us=${percentile(0.9)} p99_us=${percentile(0.99)} min_us=${samples[0].toFixed(1)} max_us=${samples[n - 1].toFixed(1)}`,
);
