const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const ts = require("typescript");

const sourcePath = path.join(__dirname, "..", "src", "incoming-stream.ts");
const source = fs.readFileSync(sourcePath, "utf8");
const output = ts.transpileModule(source, {
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.CommonJS,
    strict: true,
  },
}).outputText;
const moduleValue = { exports: {} };
new Function("module", "exports", "require", "__filename", "__dirname", output)(
  moduleValue,
  moduleValue.exports,
  require,
  sourcePath,
  path.dirname(sourcePath),
);
const { IncomingCipherContexts, IncomingFrameCoordinator, IncomingFrameStream, UNITY_HEADER_LIMIT } = moduleValue.exports;

function frame(bodyLength, marker) {
  const bytes = new Array(bodyLength + 4).fill(marker);
  bytes[0] = (bodyLength >>> 24) & 0xff;
  bytes[1] = (bodyLength >>> 16) & 0xff;
  bytes[2] = (bodyLength >>> 8) & 0xff;
  bytes[3] = bodyLength & 0xff;
  bytes[4] = (marker + 1) & 0xff;
  bytes[5] = (marker + 2) & 0xff;
  return bytes;
}

function header(bytes, first, second) {
  const copy = bytes.slice();
  copy[4] = first;
  copy[5] = second;
  return copy;
}

{
  const stream = new IncomingFrameStream(0x200000);
  const expected = frame(11851, 0x31);
  const first = stream.append(expected.slice(0, 5120));
  assert.deepEqual(first.starts, [{ id: 1, cipher4: 0x32, cipher5: 0x33 }]);
  assert.equal(first.frames.length, 0);
  assert.equal(first.error, null);
  const second = stream.append(expected.slice(5120, 10240));
  assert.equal(second.starts.length, 0);
  assert.equal(second.frames.length, 0);
  assert.equal(second.error, null);
  const third = stream.append(expected.slice(10240));
  assert.deepEqual(third.frames, [{ id: 1, bytes: expected }]);
  assert.equal(third.error, null);
}

{
  const stream = new IncomingFrameStream(0x200000);
  const firstFrame = frame(6, 0x41);
  const secondFrame = frame(9, 0x51);
  const result = stream.append(firstFrame.concat(secondFrame));
  assert.deepEqual(result.starts, [
    { id: 1, cipher4: 0x42, cipher5: 0x43 },
    { id: 2, cipher4: 0x52, cipher5: 0x53 },
  ]);
  assert.deepEqual(result.frames, [
    { id: 1, bytes: firstFrame },
    { id: 2, bytes: secondFrame },
  ]);
}

{
  const stream = new IncomingFrameStream(0x200000);
  const expected = frame(12, 0x61);
  assert.deepEqual(stream.append(expected.slice(0, 2)), { starts: [], frames: [], error: null });
  assert.deepEqual(stream.append(expected.slice(2, 5)), { starts: [], frames: [], error: null });
  assert.deepEqual(stream.append(expected.slice(5, 6)).starts, [{ id: 1, cipher4: 0x62, cipher5: 0x63 }]);
  assert.deepEqual(stream.append(expected.slice(6)).frames, [{ id: 1, bytes: expected }]);
}

{
  const stream = new IncomingFrameStream(0x200000);
  const firstFrame = frame(5, 0x21);
  const secondFrame = frame(7, 0x26);
  const first = stream.append(firstFrame.concat(secondFrame.slice(0, 2)));
  assert.deepEqual(first.frames, [{ id: 1, bytes: firstFrame }]);
  const second = stream.append(secondFrame.slice(2));
  assert.deepEqual(second.starts, [{ id: 2, cipher4: 0x27, cipher5: 0x28 }]);
  assert.deepEqual(second.frames, [{ id: 2, bytes: secondFrame }]);
}

{
  const stream = new IncomingFrameStream(0x200000);
  const invalid = stream.append([0, 0, 0, 1, 0, 0]);
  assert.equal(invalid.error, "invalid incoming frame length 1");
  assert.equal(stream.append(frame(4, 0x71)).frames.length, 0);
  stream.reset();
  assert.equal(stream.append(frame(4, 0x71)).frames.length, 1);
}

{
  const stream = new IncomingFrameStream(32);
  const invalid = stream.append([0, 0, 0, 33, 0, 0]);
  assert.equal(invalid.error, "invalid incoming frame length 33");
  assert.equal(invalid.frames.length, 0);
}

{
  const stream = new IncomingFrameStream(32);
  const invalid = stream.append(new Array(73).fill(0));
  assert.equal(invalid.error, "incoming frame buffer exceeds limit");
  assert.equal(stream.append(frame(4, 0x11)).frames.length, 0);
}

{
  const stream = new IncomingFrameStream(32);
  const first = frame(20, 0x11);
  const second = frame(20, 0x21);
  assert.deepEqual(stream.append(first.concat(second)).frames.map(value => value.bytes), [first, second]);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 6000);
  const expected = header(frame(11851, 0x31), 0x91, 0x92);
  const first = coordinator.append("candidate-a", 11, expected.slice(0, 5120));
  assert.deepEqual(first.completedFrameIds, []);
  assert.equal(first.boundCandidateId, null);
  assert.equal(coordinator.cipher("candidate-a", "engine-a", 11, 0x91, 0x01).frames.length, 0);
  const confirmed = coordinator.cipher("candidate-a", "engine-a", 11, 0x92, 0x23);
  assert.equal(confirmed.boundChanged, true);
  assert.equal(confirmed.cipherMatched, true);
  assert.equal(confirmed.boundCandidateId, "candidate-a");
  assert.equal(confirmed.frames.length, 0);
  const second = coordinator.append("candidate-a", 11, expected.slice(5120, 10240));
  assert.equal(second.frames.length, 0);
  const complete = coordinator.append("candidate-a", 11, expected.slice(10240));
  assert.equal(complete.frames.length, 1);
  assert.equal(complete.frames[0].candidateId, "candidate-a");
  assert.equal(complete.frames[0].frameId, 1);
  assert.deepEqual(complete.frames[0].bytes.slice(4, 6), [0x01, 0x23]);
  assert.equal(coordinator.cipher("candidate-a", "engine-a", 11, 0x91, 0x01).frames.length, 0);
  assert.equal(coordinator.cipher("candidate-a", "engine-a", 11, 0x92, 0x23).frames.length, 0);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 6000);
  const expected = header(frame(18, 0x41), 0xa1, 0xa2);
  const complete = coordinator.append("candidate-a", 12, expected);
  assert.deepEqual(complete.completedFrameIds, [1]);
  assert.equal(complete.frames.length, 0);
  coordinator.cipher("candidate-a", "engine-a", 12, 0xa1, 0x02);
  const ready = coordinator.cipher("candidate-a", "engine-a", 12, 0xa2, 0x34);
  assert.equal(ready.frames.length, 1);
  assert.deepEqual(ready.frames[0].bytes.slice(4, 6), [0x02, 0x34]);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 6000);
  const expected = header(frame(18, 0x41), 0xa1, 0xa2);
  coordinator.append("candidate-a", 11, expected);
  assert.equal(coordinator.cipher("candidate-a", "engine-a", 22, 0xa1, 0x02).cipherMatched, false);
  coordinator.cipher("candidate-a", "engine-a", 22, 0xa1, 0x02, "method-a", true);
  const ready = coordinator.cipher("candidate-a", "engine-a", 22, 0xa2, 0x34, "method-a", true);
  assert.equal(ready.boundCandidateId, "candidate-a");
  assert.equal(ready.cipherMatched, true);
  assert.equal(ready.frames.length, 1);
  assert.deepEqual(ready.frames[0].bytes.slice(4, 6), [0x02, 0x34]);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 6000);
  const firstFrame = header(frame(8, 0x41), 0xb1, 0xb2);
  const secondFrame = header(frame(9, 0x51), 0xc1, 0xc2);
  const complete = coordinator.append("candidate-a", 13, firstFrame.concat(secondFrame));
  assert.deepEqual(complete.completedFrameIds, [1, 2]);
  coordinator.cipher("candidate-a", "engine-a", 13, 0xb1, 0x01);
  const first = coordinator.cipher("candidate-a", "engine-a", 13, 0xb2, 0x11);
  coordinator.cipher("candidate-a", "engine-a", 13, 0xc1, 0x02);
  const second = coordinator.cipher("candidate-a", "engine-a", 13, 0xc2, 0x22);
  assert.deepEqual(first.frames.map(value => value.frameId), [1]);
  assert.deepEqual(second.frames.map(value => value.frameId), [2]);
  assert.deepEqual(first.frames[0].bytes.slice(4, 6), [0x01, 0x11]);
  assert.deepEqual(second.frames[0].bytes.slice(4, 6), [0x02, 0x22]);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 6000);
  const firstFrame = header(frame(8, 0x41), 0xd1, 0xd2);
  const secondFrame = header(frame(8, 0x51), 0xe1, 0xe2);
  coordinator.append("candidate-a", 21, firstFrame);
  coordinator.append("candidate-b", 21, secondFrame);
  coordinator.cipher("candidate-a", "engine-a", 21, 0xd1, 0x01);
  coordinator.cipher("candidate-b", "engine-b", 21, 0xe1, 0x02);
  const confirmed = coordinator.cipher("candidate-b", "engine-b", 21, 0xe2, 0x45);
  assert.equal(confirmed.boundCandidateId, "candidate-b");
  assert.deepEqual(confirmed.frames.map(value => value.candidateId), ["candidate-b"]);
  assert.equal(coordinator.cipher("candidate-a", "engine-a", 21, 0xd2, 0x34).frames.length, 0);
  assert.equal(coordinator.append("candidate-a", 21, firstFrame).completedFrameIds.length, 0);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 4001);
  const expected = header(frame(18, 0x41), 0xaa, 0xaa);
  coordinator.append("candidate-a", 14, expected);
  coordinator.cipher("candidate-a", "engine-a", 14, 0xaa, 0x34);
  const ready = coordinator.cipher("candidate-a", "engine-a", 14, 0xaa, 0x02);
  assert.equal(ready.frames.length, 1);
  assert.deepEqual(ready.frames[0].bytes.slice(4, 6), [0x02, 0x34]);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 4001);
  const expected = header(frame(18, 0x41), 0xab, 0xac);
  coordinator.append("candidate-a", 15, expected);
  coordinator.cipher("candidate-a", "engine-a", 15, 0xab, 0x02);
  coordinator.cipher("candidate-a", "engine-b", 15, 0xac, 0x34);
  const ready = coordinator.cipher("candidate-a", "engine-a", 15, 0xac, 0x34);
  assert.equal(ready.frames.length, 1);
  assert.deepEqual(ready.frames[0].bytes.slice(4, 6), [0x02, 0x34]);
}

{
  assert.equal(UNITY_HEADER_LIMIT, 6000);
  const cipherAccepted = new IncomingFrameCoordinator(0x200000, UNITY_HEADER_LIMIT - 1, UNITY_HEADER_LIMIT);
  const encrypted = header(frame(8, 0x31), 0xb1, 0xb2);
  cipherAccepted.append("candidate-a", 16, encrypted);
  cipherAccepted.cipher("candidate-a", "engine-a", 16, 0xb1, 0x10);
  const activeHeader = cipherAccepted.cipher("candidate-a", "engine-a", 16, 0xb2, 0x05);
  assert.equal(activeHeader.frames.length, 1);
  assert.deepEqual(activeHeader.frames[0].bytes.slice(4, 6), [0x10, 0x05]);

  const boundaryAccepted = new IncomingFrameCoordinator(0x200000, UNITY_HEADER_LIMIT - 1, UNITY_HEADER_LIMIT);
  boundaryAccepted.append("candidate-a", 16, encrypted);
  boundaryAccepted.cipher("candidate-a", "engine-a", 16, 0xb1, 0x17);
  const boundary = boundaryAccepted.cipher("candidate-a", "engine-a", 16, 0xb2, 0x6f);
  assert.equal(boundary.frames.length, 1);
  assert.deepEqual(boundary.frames[0].bytes.slice(4, 6), [0x17, 0x6f]);

  const cipherRejected = new IncomingFrameCoordinator(0x200000, UNITY_HEADER_LIMIT - 1, UNITY_HEADER_LIMIT);
  cipherRejected.append("candidate-a", 16, encrypted);
  cipherRejected.cipher("candidate-a", "engine-a", 16, 0xb1, 0x17);
  const overLimit = cipherRejected.cipher("candidate-a", "engine-a", 16, 0xb2, 0x70);
  assert.equal(overLimit.frames.length, 0);
  assert.equal(overLimit.boundCandidateId, null);

  const plainAccepted = new IncomingFrameCoordinator(0x200000, UNITY_HEADER_LIMIT - 1, UNITY_HEADER_LIMIT);
  const proxyId = plainAccepted.append("plain", 16, header(frame(8, 0x31), 0x0f, 0xa1));
  assert.equal(plainAccepted.plain("plain", proxyId.completedFrameIds).frames.length, 1);

  const plainRejected = new IncomingFrameCoordinator(0x200000, UNITY_HEADER_LIMIT - 1, UNITY_HEADER_LIMIT);
  const invalid = plainRejected.append("plain", 16, header(frame(8, 0x31), 0x17, 0x70));
  assert.equal(plainRejected.plain("plain", invalid.completedFrameIds).error, "invalid plaintext incoming header 6000");
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 6000);
  const expected = header(frame(16, 0x31), 0x00, 0x2a);
  const partial = coordinator.append("plain", 31, expected.slice(0, 6));
  assert.equal(coordinator.plain("plain", partial.completedFrameIds).frames.length, 0);
  assert.equal(coordinator.boundCandidateId, null);
  const complete = coordinator.append("plain", 31, expected.slice(6));
  assert.equal(complete.boundCandidateId, null);
  assert.equal(complete.frames.length, 0);
  const ready = coordinator.plain("plain", complete.completedFrameIds);
  assert.equal(ready.boundChanged, true);
  assert.equal(ready.cipherMatched, false);
  assert.equal(ready.boundCandidateId, "plain");
  assert.equal(ready.frames.length, 1);
  assert.equal(coordinator.plain("plain", complete.completedFrameIds).frames.length, 0);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 5999, 6000);
  const plaintext = coordinator.append("candidate-a", 32, header(frame(8, 0x31), 0x00, 0x2a));
  assert.equal(coordinator.plain("candidate-a", plaintext.completedFrameIds).frames.length, 1);
  const encrypted = header(frame(8, 0x41), 0xc1, 0xc2);
  coordinator.append("candidate-a", 32, encrypted);
  assert.equal(coordinator.cipher("candidate-a", "engine-new", 32, 0xc1, 0x01).cipherMatched, false);
  const matched = coordinator.cipher("candidate-a", "engine-new", 32, 0xc2, 0x23);
  assert.equal(matched.boundChanged, false);
  assert.equal(matched.boundCandidateId, "candidate-a");
  assert.equal(matched.cipherMatched, true);
  assert.deepEqual(matched.frames[0].bytes.slice(4, 6), [0x01, 0x23]);
}

{
  const contexts = new IncomingCipherContexts();
  contexts.rememberCandidate("candidate-a", "engine-a");
  assert.equal(contexts.resolveCandidate("engine-a"), "candidate-a");
  contexts.rememberCandidate("candidate-b", "engine-a");
  assert.equal(contexts.resolveCandidate("engine-a"), null);
  assert.equal(contexts.resolveCandidate("engine-a", "candidate-b"), "candidate-b");
  contexts.forgetCandidate("candidate-b");
  assert.equal(contexts.resolveCandidate("engine-a"), "candidate-a");
  const outer = contexts.enter("candidate-a", "engine-shared", 91);
  const inner = contexts.enter("candidate-b", "engine-shared", 91);
  assert.deepEqual(contexts.match(91, "engine-shared"), { candidateId: "candidate-b", current: true });
  contexts.leave(91, inner);
  assert.deepEqual(contexts.match(91, "engine-shared"), { candidateId: "candidate-a", current: true });
  contexts.leave(91, outer);
  assert.equal(contexts.match(91, "engine-shared"), null);
  const stale = contexts.enter("candidate-old", "engine-old", 92);
  contexts.reset();
  assert.deepEqual(contexts.match(92, "engine-old"), { candidateId: "candidate-old", current: false });
  const current = contexts.enter("candidate-new", "engine-old", 92);
  assert.deepEqual(contexts.match(92, "engine-old"), { candidateId: "candidate-new", current: true });
  contexts.leave(92, stale);
  assert.deepEqual(contexts.match(92, "engine-old"), { candidateId: "candidate-new", current: true });
  contexts.leave(92, current);
  assert.equal(contexts.match(92, "engine-old"), null);
  contexts.reset();
  assert.equal(contexts.resolveCandidate("engine-a", "candidate-a"), null);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 5999, 6000);
  const contexts = new IncomingCipherContexts();
  assert.equal(coordinator.reject("candidate-a", "invalid candidate").error, "invalid candidate");
  const encrypted = header(frame(8, 0x41), 0xd1, 0xd2);
  coordinator.append("candidate-b", 93, encrypted);
  const stale = contexts.enter("candidate-a", "engine-shared", 93);
  const active = contexts.enter("candidate-b", "engine-shared", 93);
  const candidateId = contexts.match(93, "engine-shared").candidateId;
  coordinator.cipher(candidateId, "engine-shared", 93, 0xd1, 0x01);
  const matched = coordinator.cipher(candidateId, "engine-shared", 93, 0xd2, 0x34);
  assert.equal(matched.boundCandidateId, "candidate-b");
  assert.equal(matched.cipherMatched, true);
  contexts.leave(93, active);
  assert.deepEqual(contexts.match(93, "engine-shared"), { candidateId: "candidate-a", current: true });
  assert.equal(coordinator.cipher("candidate-a", "engine-shared", 93, 0xd1, 0x01).cipherMatched, false);
  contexts.leave(93, stale);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 5999, 6000);
  const encrypted = header(frame(8, 0x41), 0xe1, 0xe2);
  coordinator.append("candidate-a", 95, encrypted);
  coordinator.cipher("candidate-a", "engine-a", 95, 0xe1, 0x01, "method-a");
  assert.equal(coordinator.cipher("candidate-a", "engine-a", 95, 0xe2, 0x34, "method-b").cipherMatched, false);
  const matched = coordinator.cipher("candidate-a", "engine-a", 95, 0xe2, 0x34, "method-a");
  assert.equal(matched.cipherMatched, true);
  assert.deepEqual(matched.frames[0].bytes.slice(4, 6), [0x01, 0x34]);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 5999, 6000);
  const distinct = header(frame(8, 0x41), 0xe1, 0xe2);
  coordinator.append("candidate-a", 94, distinct);
  coordinator.cipher("candidate-a", "engine-a", 94, 0xe1, 0x02);
  assert.equal(coordinator.cipher("candidate-a", "engine-a", 94, 0xe2, 0x34).frames.length, 1);
  const equal = header(frame(8, 0x51), 0xaa, 0xaa);
  coordinator.append("candidate-a", 94, equal);
  coordinator.cipher("candidate-a", "engine-a", 94, 0xaa, 0x01);
  const ready = coordinator.cipher("candidate-a", "engine-a", 94, 0xaa, 0x56);
  assert.deepEqual(ready.frames[0].bytes.slice(4, 6), [0x01, 0x56]);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 6000);
  const invalid = header(frame(8, 0x31), 0x20, 0x00);
  const complete = coordinator.append("bad", 41, invalid);
  const rejected = coordinator.plain("bad", complete.completedFrameIds);
  assert.equal(rejected.error, "invalid plaintext incoming header 8192");
  assert.equal(coordinator.append("bad", 41, header(frame(8, 0x31), 0, 1)).completedFrameIds.length, 0);
  const other = coordinator.append("good", 42, header(frame(8, 0x31), 0, 1));
  assert.equal(coordinator.plain("good", other.completedFrameIds).frames.length, 1);
  coordinator.reset();
  assert.equal(coordinator.boundCandidateId, null);
  assert.equal(coordinator.pendingCount, 0);
  const afterReset = coordinator.append("bad", 41, header(frame(8, 0x31), 0, 1));
  assert.equal(coordinator.plain("bad", afterReset.completedFrameIds).frames.length, 1);
}

{
  const coordinator = new IncomingFrameCoordinator(32, 4000, 6000);
  const invalid = coordinator.append("bad", 51, [0, 0, 0, 33, 0, 0]);
  assert.equal(invalid.error, "invalid incoming frame length 33");
  assert.equal(coordinator.append("bad", 51, header(frame(4, 0x11), 0, 1)).completedFrameIds.length, 0);
  coordinator.reset();
  const complete = coordinator.append("bad", 51, header(frame(4, 0x11), 0, 1));
  assert.equal(coordinator.plain("bad", complete.completedFrameIds).frames.length, 1);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 6000);
  const expected = header(frame(20, 0x31), 0xf1, 0xf2);
  coordinator.append("candidate-a", 61, expected.slice(0, 10));
  coordinator.append("candidate-a", 62, expected.slice(10));
  coordinator.cipher("candidate-a", "engine-a", 62, 0xf1, 0x03);
  const ready = coordinator.cipher("candidate-a", "engine-a", 62, 0xf2, 0x45);
  assert.equal(ready.boundCandidateId, "candidate-a");
  assert.equal(ready.frames.length, 1);
}

{
  const coordinator = new IncomingFrameCoordinator(32, 4000, 6000);
  assert.equal(coordinator.reject("candidate-a", "invalid range").error, "invalid range");
  assert.equal(coordinator.reject("candidate-a", "invalid range").error, null);
  coordinator.reset();
  assert.equal(coordinator.reject("candidate-a", "invalid range").error, "invalid range");
}

{
  const coordinator = new IncomingFrameCoordinator(32, 4000, 6000);
  const initial = coordinator.append("candidate-a", 73, header(frame(4, 0x11), 0, 1));
  assert.equal(coordinator.plain("candidate-a", initial.completedFrameIds).frames.length, 1);
  assert.equal(coordinator.reject("candidate-a", "bound corruption").error, "bound corruption");
  assert.equal(coordinator.append("candidate-a", 73, header(frame(4, 0x11), 0, 2)).completedFrameIds.length, 0);
  coordinator.reset();
  const recovered = coordinator.append("candidate-a", 73, header(frame(4, 0x11), 0, 2));
  assert.equal(coordinator.plain("candidate-a", recovered.completedFrameIds).frames.length, 1);
}

{
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 6000, 1);
  const firstFrame = header(frame(4, 0x11), 0x81, 0x82);
  const secondFrame = header(frame(4, 0x21), 0x91, 0x92);
  const rejected = coordinator.append("candidate-a", 72, firstFrame.concat(secondFrame));
  assert.equal(rejected.error, "incoming frame state exceeds limit");
  assert.equal(coordinator.pendingCount, 0);
  assert.equal(coordinator.append("candidate-a", 72, firstFrame).completedFrameIds.length, 0);
}

{
  const coordinator = new IncomingFrameCoordinator(32, 5999, 6000, 16, 30);
  const first = header(frame(12, 0x11), 0x81, 0x82);
  const second = header(frame(12, 0x21), 0x91, 0x92);
  const rejected = coordinator.append("candidate-a", 96, first.concat(second));
  assert.equal(rejected.error, "incoming frame payload state exceeds limit");
  assert.equal(coordinator.pendingCount, 0);
  assert.equal(coordinator.pendingByteCount, 0);
}

{
  let seed = 0x6d2b79f5;
  const random = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed;
  };
  const coordinator = new IncomingFrameCoordinator(0x200000, 4000, 6000);
  const expected = [];
  let stream = [];
  for (let index = 0; index < 200; index++) {
    const packet = header(frame(2 + random() % 200, random() & 0xff), (index >>> 8) & 0xff, index & 0xff);
    expected.push(packet);
    stream = stream.concat(packet);
  }
  const actual = [];
  let position = 0;
  while (position < stream.length) {
    const count = Math.min(stream.length - position, 1 + random() % 5120);
    const appended = coordinator.append("plain", 81, stream.slice(position, position + count));
    const ready = coordinator.plain("plain", appended.completedFrameIds);
    actual.push(...appended.frames.map(value => value.bytes), ...ready.frames.map(value => value.bytes));
    position += count;
  }
  assert.deepEqual(actual, expected);
}

console.log("incoming stream tests passed");
