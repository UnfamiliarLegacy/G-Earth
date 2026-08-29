import "frida-il2cpp-bridge";
import { IncomingCipherContexts, IncomingCoordinatorResult, IncomingFrameCoordinator, UNITY_HEADER_LIMIT } from "./incoming-stream";

function log(message: string): void { try { console.log(message); } catch (e) {} }

const debugHeaders = false;

// bridge protocol, mirrors the java side
const FRAME_NOTIFY = 0;
const FRAME_INTERCEPT = 1;
const DIR_TO_CLIENT = 0;
const DIR_TO_SERVER = 1;
const TAG_VERDICT = 0x10;
const TAG_INJECT = 0x20;
const MAX_HEADER = UNITY_HEADER_LIMIT - 1;
const MAX_PACKET_LENGTH = 0x200000;
const MAX_FRAME_LENGTH = MAX_PACKET_LENGTH - 4;
const MAX_BRIDGE_PAYLOAD_LENGTH = MAX_PACKET_LENGTH + 1;

// port and cookie come from frida-inject -P through rpc.exports.init
let bridgeport = 9399;
let cookie = "";
rpc.exports = {
  init(stage: string, params: any): void {
    if (params) {
      if (params.port) bridgeport = params.port;
      if (params.cookie) cookie = params.cookie;
    }
  },
};
const CLIENT_VERSION = "UNITY20";

// raw socket, fridas Socket api is async but the hooks run sync
const winsock = Module.load("ws2_32.dll");
const wsaStartup = new NativeFunction(winsock.getExportByName("WSAStartup"), "int", ["uint32", "pointer"]);
const openSocket = new NativeFunction(winsock.getExportByName("socket"), "uint32", ["int", "int", "int"]);
const connectSocket = new NativeFunction(winsock.getExportByName("connect"), "int", ["uint32", "pointer", "int"]);
const socketSend = new NativeFunction(winsock.getExportByName("send"), "int", ["uint32", "pointer", "int", "int"], { scheduling: "exclusive" });
const socketRecv = new NativeFunction(winsock.getExportByName("recv"), "int", ["uint32", "pointer", "int", "int"], { scheduling: "exclusive" });
const closeSocket = new NativeFunction(winsock.getExportByName("closesocket"), "int", ["uint32"]);
const htons = new NativeFunction(winsock.getExportByName("htons"), "uint16", ["uint16"]);
const setSockOpt = new NativeFunction(winsock.getExportByName("setsockopt"), "int", ["uint32", "int", "int", "pointer", "int"]);
const ioctlSocket = new NativeFunction(winsock.getExportByName("ioctlsocket"), "int", ["uint32", "int", "pointer"]);
const FIONREAD = 0x4004667f;
const INVALID_SOCKET = 0xffffffff;

const kernel32 = Module.load("kernel32.dll");
const initCriticalSection = new NativeFunction(kernel32.getExportByName("InitializeCriticalSection"), "void", ["pointer"]);
const enterCriticalSection = new NativeFunction(kernel32.getExportByName("EnterCriticalSection"), "void", ["pointer"]);
const leaveCriticalSection = new NativeFunction(kernel32.getExportByName("LeaveCriticalSection"), "void", ["pointer"]);
const getCurrentProcess = new NativeFunction(kernel32.getExportByName("GetCurrentProcess"), "pointer", []);
const terminateProcess = new NativeFunction(kernel32.getExportByName("TerminateProcess"), "int", ["pointer", "uint"]);
const criticalSection = Memory.alloc(64); initCriticalSection(criticalSection);

let bridgeSocket = INVALID_SOCKET, bridgeReady = false;

function connectBridge(revision: string, host: string): boolean {
  const wsaData = Memory.alloc(512);
  wsaStartup(0x0202, wsaData);
  const sock = (openSocket(2, 1, 6) as number);
  if (sock === INVALID_SOCKET) return false;
  const addr = Memory.alloc(16);
  addr.writeU16(2);
  addr.add(2).writeU16(htons(bridgeport) as number);
  addr.add(4).writeU32(0x0100007f);
  if ((connectSocket(sock, addr, 16) as number) !== 0) { closeSocket(sock); return false; }
  bridgeSocket = sock;
  const recvTimeout = Memory.alloc(4); recvTimeout.writeU32(2000);
  setSockOpt(sock, 0xffff, 0x1006, recvTimeout, 4);
  const marker = Memory.alloc(1); marker.writeU8(0xff);
  if (!sendAll(marker, 1) || !sendstr(cookie) || !sendstr(revision) || !sendstr(host)) { closeSocket(sock); bridgeSocket = INVALID_SOCKET; return false; }
  bridgeReady = true;
  return true;
}
function sendstr(text: string): boolean {
  const bytes = Memory.allocUtf8String(text);
  const len = text.length;
  const head = Memory.alloc(4);
  head.writeU8((len >> 24) & 0xff); head.add(1).writeU8((len >> 16) & 0xff); head.add(2).writeU8((len >> 8) & 0xff); head.add(3).writeU8(len & 0xff);
  if (!sendAll(head, 4)) return false;
  return len > 0 ? sendAll(bytes, len) : true;
}
function sendAll(buffer: NativePointer, len: number): boolean { let sent = 0; while (sent < len) { const written = (socketSend(bridgeSocket, buffer.add(sent), len - sent, 0) as number); if (written <= 0) { bridgeReady = false; return false; } sent += written; } return true; }
function recvAll(buffer: NativePointer, len: number): boolean { let received = 0; while (received < len) { const chunk = (socketRecv(bridgeSocket, buffer.add(received), len - received, 0) as number); if (chunk <= 0) return false; received += chunk; } return true; }

let gameHost = "";
let readyToConnect = false;
function looksLikeGameHost(name: string): boolean { const lower = name.toLowerCase(); return lower.indexOf("game") === 0 && lower.indexOf("habbo") >= 0; }
function ensureConnected(): void {
  if (shuttingDown || bridgeReady || !readyToConnect) return;
  if (connectBridge(CLIENT_VERSION, gameHost)) log("[agent] G-Earth bridge connected host=" + (gameHost || "(unknown)"));
}
function captureHost(name: string | null): void {
  if (name && !gameHost && looksLikeGameHost(name)) { gameHost = name; readyToConnect = true; log("[host] game host " + name); ensureConnected(); }
}
function captureHostFromMemory(): void {
  if (gameHost) return;
  try {
    const objs = Il2Cpp.gc.choose(Il2Cpp.corlib.class("System.String"));
    for (let i = 0; i < objs.length; i++) {
      const handle = objs[i].handle;
      let value: string | null;
      try { const len = handle.add(8).readS32(); if (len < 12 || len > 200) continue; value = handle.add(12).readUtf16String(len); } catch (e) { continue; }
      if (!value || value.toLowerCase().indexOf("habbo") < 0) continue;
      const match = value.match(/^wss?:\/\/([^/:]+)/i);
      const candidate = match ? match[1] : value;
      const lower = candidate.toLowerCase();
      if (lower.indexOf("game") === 0 && lower.indexOf(".habbo") > 0 && candidate.indexOf("/") < 0) { gameHost = candidate; log("[host] resolved from memory " + candidate); return; }
    }
  } catch (e) { log("[host] memory scan failed " + e); }
}
try { const dns = winsock.findExportByName("GetAddrInfoW"); if (dns) Interceptor.attach(dns, { onEnter(args) { try { if (!args[0].isNull()) captureHost(args[0].readUtf16String()); } catch (e) {} } }); } catch (e) {}
try { const dns = winsock.findExportByName("getaddrinfo"); if (dns) Interceptor.attach(dns, { onEnter(args) { try { if (!args[0].isNull()) captureHost(args[0].readUtf8String()); } catch (e) {} } }); } catch (e) {}

let outCount = 0, inCount = 0;
let outBusy = false;
const frameHeader = Memory.alloc(6);
const readHeader = Memory.alloc(5);
const readBuffer = Memory.alloc(MAX_BRIDGE_PAYLOAD_LENGTH);
function sendFrameRaw(type: number, direction: number, bytes: number[]): boolean {
  if (!bridgeReady) return false;
  const len = bytes.length; if (len > MAX_PACKET_LENGTH) return false; const payload = Memory.alloc(len || 1);
  for (let index = 0; index < len; index++) payload.add(index).writeU8(bytes[index]);
  frameHeader.writeU8(type); frameHeader.add(1).writeU8(direction);
  frameHeader.add(2).writeU8((len >> 24) & 0xff); frameHeader.add(3).writeU8((len >> 16) & 0xff);
  frameHeader.add(4).writeU8((len >> 8) & 0xff); frameHeader.add(5).writeU8(len & 0xff);
  if (!sendAll(frameHeader, 6)) return false;
  if (len > 0 && !sendAll(payload, len)) return false;
  return true;
}
function sendFrame(type: number, direction: number, bytes: number[]): boolean { enterCriticalSection(criticalSection); try { return sendFrameRaw(type, direction, bytes); } finally { leaveCriticalSection(criticalSection); } }
function notify(direction: number, bytes: number[]): void { sendFrame(FRAME_NOTIFY, direction, bytes); }

function readFrame(): { tag: number; bytes: Uint8Array } | null {
  if (!recvAll(readHeader, 5)) return null;
  const tag = readHeader.readU8();
  const len = (readHeader.add(1).readU8() << 24) | (readHeader.add(2).readU8() << 16) | (readHeader.add(3).readU8() << 8) | readHeader.add(4).readU8();
  if (len < 0 || len > MAX_BRIDGE_PAYLOAD_LENGTH) return null;
  if (len > 0 && !recvAll(readBuffer, len)) return null;
  return { tag, bytes: len > 0 ? new Uint8Array(readBuffer.readByteArray(len)!) : new Uint8Array(0) };
}
function queueInject(frame: Uint8Array): void {
  if (frame.length < 7) return;
  const direction = frame[0]; const packet: number[] = []; for (let index = 1; index < frame.length; index++) packet.push(frame[index]);
  if (packet.length < 6) return;
  const header = (packet[4] << 8) | packet[5];
  injectQueue.push({ direction, header, body: packet.slice(6) });
  log("[inject] queued from bridge dir=" + direction + " hdr=" + header + " bodyLen=" + (packet.length - 6));
}
function interceptOut(bytes: number[]): { blocked: boolean; bytes: number[] } | null {
  if (!bridgeReady || outBusy) { sendFrame(FRAME_NOTIFY, DIR_TO_SERVER, bytes); return null; }
  outBusy = true;
  enterCriticalSection(criticalSection);
  try {
    if (!sendFrameRaw(FRAME_INTERCEPT, DIR_TO_SERVER, bytes)) { bridgeReady = false; return null; }
    let guard = 0;
    for (; ;) {
      if (++guard > 4096) { bridgeReady = false; return null; }
      const frame = readFrame();
      if (!frame) { bridgeReady = false; return null; }
      if (frame.tag === TAG_INJECT) { queueInject(frame.bytes); continue; }
      if (frame.tag === TAG_VERDICT) { const payload = frame.bytes; const out: number[] = []; for (let index = 1; index < payload.length; index++) out.push(payload[index]); return { blocked: payload.length > 0 && payload[0] === 1, bytes: out }; }
    }
  } finally { leaveCriticalSection(criticalSection); outBusy = false; }
}

// il2cpp array offsets, 32 vs 64 bit
const pointerSize = Process.pointerSize;
const ARRAY_LENGTH_OFFSET = pointerSize === 8 ? 24 : 12;
const ARRAY_DATA_OFFSET = pointerSize === 8 ? 32 : 16;

function readArray(array: NativePointer, offset: number, length: number): number[] {
  const total = array.add(ARRAY_LENGTH_OFFSET).readS32();
  let available = (length && length > 0) ? Math.min(length, total - offset) : (total - offset);
  if (available < 4 || available > MAX_PACKET_LENGTH) return [];
  const lengthBytes = new Uint8Array(array.add(ARRAY_DATA_OFFSET + offset).readByteArray(4)!);
  const packetLength = (lengthBytes[0] << 24) | (lengthBytes[1] << 16) | (lengthBytes[2] << 8) | lengthBytes[3];
  // buffer is pooled and oversized, trim to the first frame
  let count = available;
  if (packetLength >= 2 && packetLength + 4 <= available) count = packetLength + 4;
  const result: number[] = [];
  const data = new Uint8Array(array.add(ARRAY_DATA_OFFSET + offset).readByteArray(count)!);
  for (let index = 0; index < count; index++) result.push(data[index]);
  return result;
}
function readChunk(array: NativePointer, offset: number, length: number): number[] | null {
  const total = array.add(ARRAY_LENGTH_OFFSET).readS32();
  if (total < 0 || offset < 0 || length <= 0 || length > MAX_PACKET_LENGTH || offset > total || length > total - offset) return null;
  const raw = array.add(ARRAY_DATA_OFFSET + offset).readByteArray(length);
  if (raw === null) return null;
  const result: number[] = [];
  const data = new Uint8Array(raw);
  for (let index = 0; index < length; index++) result.push(data[index]);
  return result;
}
function isHabbo(bytes: number[]): boolean {
  if (bytes.length < 6) return false;
  const len = ((bytes[0] & 0xff) << 24) | ((bytes[1] & 0xff) << 16) | ((bytes[2] & 0xff) << 8) | (bytes[3] & 0xff);
  return len >= 2 && len <= MAX_FRAME_LENGTH;
}
function sameBytes(first: number[], second: number[]): boolean { if (first.length !== second.length) return false; for (let index = 0; index < first.length; index++) if ((first[index] & 0xff) !== (second[index] & 0xff)) return false; return true; }
function splitFrames(array: NativePointer, total: number): number[][] | null {
  const frames: number[][] = []; let position = 0;
  while (position + 4 <= total) {
    const frameLength = (array.add(ARRAY_DATA_OFFSET + position).readU8() << 24) | (array.add(ARRAY_DATA_OFFSET + position + 1).readU8() << 16) | (array.add(ARRAY_DATA_OFFSET + position + 2).readU8() << 8) | array.add(ARRAY_DATA_OFFSET + position + 3).readU8();
    if (frameLength < 2 || position + 4 + frameLength > total) return null;
    frames.push(readArray(array, position, 4 + frameLength));
    position += 4 + frameLength;
  }
  return position === total ? frames : null;
}

// recent cipher in/out pairs tagged by thread, used to recover the plaintext out header on the send thread
type CipherRecord = { input: number; output: number; engine: NativePointer; threadId: number; address: NativePointer; method: NativePointer };
const cipherLog: CipherRecord[] = []; const CIPHER_LOG_MAX = 256;
function recordCipher(input: number, output: number, engine: NativePointer, threadId: number, address: NativePointer, method: NativePointer): void { cipherLog.push({ input, output, engine, threadId, address, method }); if (cipherLog.length > CIPHER_LOG_MAX) cipherLog.shift(); }
function removeCipherRecords(engine: NativePointer): void { for (let index = cipherLog.length - 1; index >= 0; index--) if (cipherLog[index].engine.equals(engine)) cipherLog.splice(index, 1); }
function findCipherPair(output4: number, output5: number, threadId: number): { record4: CipherRecord; record5: CipherRecord } | null {
  for (let index4 = cipherLog.length - 1; index4 >= 0; index4--) {
    const record4 = cipherLog[index4];
    if (record4.output !== output4 || record4.threadId !== threadId) continue;
    for (let index5 = Math.min(cipherLog.length - 1, index4 + 16); index5 >= Math.max(0, index4 - 16); index5--) {
      if (index5 === index4) continue;
      const record5 = cipherLog[index5];
      if (record5.output !== output5 || record5.threadId !== threadId || !record5.engine.equals(record4.engine) || !record5.address.equals(record4.address) || !record5.method.equals(record4.method)) continue;
      if ((record4.input << 8 | record5.input) <= MAX_HEADER) return { record4, record5 };
    }
  }
  return null;
}

const incomingCoordinator = new IncomingFrameCoordinator(MAX_FRAME_LENGTH, MAX_HEADER, MAX_HEADER + 1);
const incomingCipherContexts = new IncomingCipherContexts();
const incomingReturnAddressesById = new Map<string, NativePointer>();
let configuredIncomingId: string | null = null;
let cipherActive = false;
let cipherGeneration = 1;
function resetCipherState(): void {
  cipherGeneration++;
  outEngine = null; inEngine = null; cipherActive = false;
  cipherFn = null; cipherMethod = NULL; outCipherAddress = null;
  outThreadId = 0; instantInject = false;
  cipherLog.length = 0; incomingCoordinator.reset(); incomingCipherContexts.reset(); incomingReturnAddressesById.clear();
  configuredIncomingId = null; resetToClientBinding(); injectQueue.length = 0; toClientQueue.length = 0;
  log("[agent] relogin detected, cipher state reset");
}
function isHello(bytes: number[]): boolean {
  if (!(bytes.length >= 6 && bytes[4] === 0x0f && bytes[5] === 0xa0)) return false;
  for (let index = 6; index + 4 < bytes.length; index++) if (bytes[index] === 85 && bytes[index + 1] === 78 && bytes[index + 2] === 73 && bytes[index + 3] === 84 && bytes[index + 4] === 89) return true;
  return false;
}

// injection state
let cipherFn: NativeFunction<number, [NativePointerValue, number, NativePointerValue]> | null = null;
let cipherMethod: NativePointer = NULL;
let outCipherAddress: NativePointer | null = null;
let outEngine: NativePointer | null = null;
let inEngine: NativePointer | null = null;
let outSendFn: NativeFunction<void, [NativePointerValue, NativePointerValue, NativePointerValue]> | null = null;
let outSendThis: NativePointer = NULL;
let outSendMethod: NativePointer = NULL;
let byteClass: Il2Cpp.Class | null = null;
let injecting = false;
let outThreadId = 0;
let instantInject = false;
const injectQueue: { direction: number; header: number; body: number[] }[] = [];

function lockOutCipher(record: CipherRecord): boolean {
  if (outEngine && !outEngine.equals(record.engine)) return false;
  if (outEngine && outCipherAddress && outCipherAddress.equals(record.address) && cipherMethod.equals(record.method) && cipherFn) return true;
  outEngine = record.engine;
  outCipherAddress = record.address;
  cipherFn = new NativeFunction(record.address, "int", ["pointer", "int", "pointer"]);
  cipherMethod = record.method;
  log("[eng] outEngine locked " + record.engine + " cipher=0x" + record.address.sub(Il2Cpp.module.base).toString(16) + " tid=" + Process.getCurrentThreadId());
  return true;
}

function encryptByte(value: number): number { try { return (cipherFn!(outEngine!, value, cipherMethod) as number) & 0xff; } catch (e) { return value; } }
function buildOutPacket(header: number, body: number[]): number[] {
  const len = 2 + body.length;
  const packet = new Array(4 + len);
  packet[0] = (len >>> 24) & 0xff; packet[1] = (len >>> 16) & 0xff; packet[2] = (len >>> 8) & 0xff; packet[3] = len & 0xff;
  packet[4] = (header >>> 8) & 0xff; packet[5] = header & 0xff;
  for (let index = 0; index < body.length; index++) packet[6 + index] = body[index] & 0xff;
  const enc5 = encryptByte(packet[5]), enc4 = encryptByte(packet[4]); packet[5] = enc5; packet[4] = enc4;
  return packet;
}
function injectToServer(header: number, body: number[]): boolean {
  injecting = true;
  try {
    const bytes = buildOutPacket(header, body);
    const byteArray = Il2Cpp.array<number>(byteClass!, bytes);
    outSendFn!(outSendThis, byteArray.handle, outSendMethod);
    return true;
  } catch (e) { logErr("inject-server", e); return false; }
  finally { injecting = false; }
}

const ioctlResult = Memory.alloc(4), injectHeader = Memory.alloc(5), injectBuffer = Memory.alloc(MAX_BRIDGE_PAYLOAD_LENGTH);
function pollInjects(): void {
  if (!bridgeReady) return;
  for (let guard = 0; guard < 64; guard++) {
    if ((ioctlSocket(bridgeSocket, FIONREAD, ioctlResult) as number) !== 0) return;
    const available = ioctlResult.readU32();
    if (available < 5) return;
    if ((socketRecv(bridgeSocket, injectHeader, 5, 2) as number) !== 5) return;
    const tag = injectHeader.readU8();
    const len = (injectHeader.add(1).readU8() << 24) | (injectHeader.add(2).readU8() << 16) | (injectHeader.add(3).readU8() << 8) | injectHeader.add(4).readU8();
    if (len < 0 || len > MAX_BRIDGE_PAYLOAD_LENGTH) { bridgeReady = false; return; }
    if (available < 5 + len) return;
    if (!recvAll(injectHeader, 5)) { bridgeReady = false; return; }
    if (len > 0 && !recvAll(injectBuffer, len)) { bridgeReady = false; return; }
    if (tag === TAG_INJECT) { const frame = len > 0 ? new Uint8Array(injectBuffer.readByteArray(len)!) : new Uint8Array(0); queueInject(frame); }
  }
}
function flushInjects(): void {
  if (!injectQueue.length) return;
  const pendingServer: { direction: number; header: number; body: number[] }[] = [];
  let queued: { direction: number; header: number; body: number[] } | undefined;
  while ((queued = injectQueue.shift())) {
    if (queued.direction === DIR_TO_SERVER) {
      if (byteClass && outEngine && cipherFn && outSendFn && !outSendThis.isNull()) injectToServer(queued.header, queued.body);
      else pendingServer.push(queued);
    }
    else toClientQueue.push({ header: queued.header, body: queued.body });
  }
  if (pendingServer.length) injectQueue.unshift(...pendingServer);
}

function interceptBatch(array: NativePointer, total: number, frames: number[][], args: InvocationArguments): void {
  const outFrames: number[][] = []; let changed = false;
  const sendThread = Process.getCurrentThreadId();
  for (const frame of frames) {
    const pair = findCipherPair(frame[4], frame[5], sendThread);
    if (!pair) { if (bridgeReady && ((frame[4] << 8) | frame[5]) <= MAX_HEADER) notify(DIR_TO_SERVER, frame); outFrames.push(frame); continue; }
    const { record4: match4, record5: match5 } = pair;
    if (!lockOutCipher(match4)) { outFrames.push(frame); continue; }
    const keystream4 = frame[4] ^ match4.input, keystream5 = frame[5] ^ match5.input;
    const plain = frame.slice(); plain[4] = match4.input; plain[5] = match5.input;
    cipherActive = true;
    outCount++;
    let outFrame = frame;
    if (bridgeReady && cipherActive) {
      const verdict = interceptOut(plain);
      if (verdict) {
        if (verdict.blocked) { const blockedReply = [0, 0, 0, 2, 0, 196]; blockedReply[4] ^= keystream4; blockedReply[5] ^= keystream5; outFrame = blockedReply; changed = true; }
        else if (verdict.bytes && verdict.bytes.length >= 6 && isHabbo(verdict.bytes) && !sameBytes(verdict.bytes, plain)) { const rewritten = verdict.bytes.slice(); rewritten[4] ^= keystream4; rewritten[5] ^= keystream5; outFrame = rewritten; changed = true; }
      }
    } else if (bridgeReady) { notify(DIR_TO_SERVER, plain); }
    outFrames.push(outFrame);
  }
  let extra: number[] = [];
  if (injectQueue.length && byteClass && outEngine && cipherFn) {
    injecting = true;
    try { let queued: { direction: number; header: number; body: number[] } | undefined; while ((queued = injectQueue.shift())) { if (queued.direction === DIR_TO_SERVER) extra = extra.concat(buildOutPacket(queued.header, queued.body)); else toClientQueue.push({ header: queued.header, body: queued.body }); } }
    catch (e) { logErr("batch-inject", e); } finally { injecting = false; }
  }
  if (!changed && extra.length === 0) return;
  let combined: number[] = [];
  for (const outFrame of outFrames) combined = combined.concat(outFrame);
  if (extra.length) combined = combined.concat(extra);
  if (combined.length === total) {
    for (let index = 0; index < combined.length; index++) array.add(ARRAY_DATA_OFFSET + index).writeU8(combined[index]);
  } else {
    const byteArray = Il2Cpp.array<number>(byteClass!, combined);
    args[1] = byteArray.handle;
  }
}

// toclient inject, fresh reader with the cipher nulled so the plaintext header survives, then dispatch
const toClientQueue: { header: number; body: number[] }[] = [];
let toClientReaderClass: Il2Cpp.Class | null = null;
let toClientCtor: NativeFunction<void, [NativePointerValue, NativePointerValue, NativePointerValue, NativePointerValue]> | null = null;
let toClientRecv: NativeFunction<void, [NativePointerValue, NativePointerValue, number, number, NativePointerValue]> | null = null;
let toClientDispatch: NativeFunction<void, [NativePointerValue, NativePointerValue]> | null = null;
let toClientCipherOffset = -1, toClientCtorArg0Offset = -1, toClientCtorArg1Offset = -1;
let toClientCtorArg0: NativePointer = NULL, toClientCtorArg1: NativePointer = NULL;
let toClientDispatchTarget: NativePointer = NULL;
let toClientByteClass: Il2Cpp.Class | null = null;
let toClientReady = false, toClientInjecting = false;
let toClientGeneration = 0;
let toClientDispatchListener: { detach(): void } | null = null;
const rvaOf = (address: NativePointer) => "0x" + address.sub(Il2Cpp.module.base).toString(16);

function resetToClientBinding(): void {
  toClientGeneration++;
  if (toClientDispatchListener) { try { toClientDispatchListener.detach(); } catch (e) {} toClientDispatchListener = null; }
  toClientReaderClass = null; toClientCtor = null; toClientRecv = null; toClientDispatch = null;
  toClientCipherOffset = -1; toClientCtorArg0Offset = -1; toClientCtorArg1Offset = -1;
  toClientCtorArg0 = NULL; toClientCtorArg1 = NULL; toClientDispatchTarget = NULL;
  toClientReady = false; toClientInjecting = false;
}

function findReaderCtor(klass: Il2Cpp.Class): { address: NativePointer; param0Type: string; param1Type: string } | null {
  for (const method of klass.methods) {
    if (method.name === ".ctor" && method.parameterCount === 2) {
      const param0Type = method.parameters[0].type.name, param1Type = method.parameters[1].type.name;
      if (param0Type.indexOf("System.") !== 0 && param1Type.indexOf("System.") !== 0) { let address: NativePointer; try { address = method.virtualAddress; } catch (e) { continue; } if (!address.isNull()) return { address, param0Type, param1Type }; }
    }
  }
  return null;
}
function fieldOffsetByType(klass: Il2Cpp.Class, typeName: string): number {
  for (const field of klass.fields) if (field.type.name === typeName) return field.offset;
  return -1;
}
function setupToClient(cand: Cand): boolean {
  try {
    const ctor = findReaderCtor(cand.klass); if (!ctor) { logErr("tc-setup", "no reader ctor"); return false; }
    const recv = new NativeFunction(cand.address, "void", ["pointer", "pointer", "int", "int", "pointer"]);
    const ctorFunction = new NativeFunction(ctor.address, "void", ["pointer", "pointer", "pointer", "pointer"]);
    const ctorArg0Offset = fieldOffsetByType(cand.klass, ctor.param0Type);
    const ctorArg1Offset = fieldOffsetByType(cand.klass, ctor.param1Type);
    if (ctorArg0Offset < 0 || ctorArg1Offset < 0) { logErr("tc-setup", "field offset not found"); return false; }
    toClientRecv = recv;
    toClientCtor = ctorFunction;
    toClientCipherOffset = cand.cipherOffset;
    toClientCtorArg0Offset = ctorArg0Offset;
    toClientCtorArg1Offset = ctorArg1Offset;
    toClientReaderClass = cand.klass;
    log("[tc] recvFn " + rvaOf(cand.address) + " ctorFn " + rvaOf(ctor.address) + " cipherOff 0x" + toClientCipherOffset.toString(16) + " regOff 0x" + toClientCtorArg0Offset.toString(16) + " arg2Off 0x" + toClientCtorArg1Offset.toString(16));
    return true;
  } catch (e) { logErr("tc-setup", e); return false; }
}
function injectToClient(header: number, body: number[]): void {
  if (!toClientReady || shuttingDown) return;
  toClientInjecting = true;
  try {
    const fresh = toClientReaderClass!.alloc();
    toClientCtor!(fresh.handle, toClientCtorArg0, toClientCtorArg1, NULL);
    fresh.handle.add(toClientCipherOffset).writePointer(NULL);
    const len = 2 + body.length;
    const packet = [(len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff, (header >>> 8) & 0xff, header & 0xff].concat(body);
    const byteArray = Il2Cpp.array<number>(toClientByteClass!, packet);
    toClientRecv!(fresh.handle, byteArray.handle, 0, packet.length, NULL);
    toClientDispatch!(fresh.handle, toClientDispatchTarget);
    log("[tc] injected toclient hdr=" + header + " len=" + packet.length + " tid=" + Process.getCurrentThreadId());
  } catch (e) { logErr("tc-inject", e); } finally { toClientInjecting = false; }
}
function findToClientDispatch(returnAddress: NativePointer, generation: number): boolean {
  if (generation !== toClientGeneration) return false;
  try {
    let cursor = returnAddress;
    const base = Il2Cpp.module.base, size = Il2Cpp.module.size;
    for (let step = 0; step < 48; step++) {
      const instruction = Instruction.parse(cursor);
      if (instruction.mnemonic === "call") {
        const match = instruction.opStr.match(/0x[0-9a-f]+/i);
        if (match) { const target = ptr(match[0]); if (target.compare(base) > 0 && target.compare(base.add(size)) < 0) { const dispatch: NativeFunction<void, [NativePointerValue, NativePointerValue]> = new NativeFunction(target, "void", ["pointer", "pointer"]); hookDispatch(target, generation); if (generation !== toClientGeneration) return false; toClientDispatch = dispatch; log("[tc] dispatchFn " + rvaOf(target)); return true; } }
      }
      if (instruction.mnemonic === "ret") break; cursor = instruction.next;
    }
  } catch (e) { logErr("tc-disc", e); }
  return false;
}
function hookDispatch(address: NativePointer, generation: number): void {
  toClientDispatchListener = Interceptor.attach(address, {
    onEnter(args) {
      if (generation !== toClientGeneration || toClientInjecting || toClientReady) return;
      try {
        const reader = args[0]; toClientDispatchTarget = args[1]; toClientReaderClass = new Il2Cpp.Object(reader).class;
        toClientCtorArg0 = reader.add(toClientCtorArg0Offset).readPointer(); toClientCtorArg1 = reader.add(toClientCtorArg1Offset).readPointer();
        if (!toClientDispatchTarget.isNull() && !toClientCtorArg0.isNull() && toClientByteClass) { toClientReady = true; log("[tc] ready, toclient inject armed"); }
      } catch (e) { logErr("tc-cap", e); }
    }
  });
}

let errorCount = 0;
function logErr(tag: string, error: unknown): void { if (errorCount < 40) { errorCount++; log("[err:" + tag + "] " + error); } }
let shuttingDown = false;
const timers: any[] = [];
function every(ms: number, callback: () => void): any { const timerId = setInterval(callback, ms); timers.push(timerId); return timerId; }
function teardown(why: string): void {
  if (shuttingDown) return; shuttingDown = true;
  try { log("[agent] teardown (" + why + ") clean exit"); } catch (e) {}
  try { timers.forEach(timerId => { try { clearInterval(timerId); } catch (e) {} }); } catch (e) {}
  try { if (bridgeSocket !== INVALID_SOCKET) { closeSocket(bridgeSocket); bridgeSocket = INVALID_SOCKET; bridgeReady = false; } } catch (e) {}
  try { Interceptor.detachAll(); } catch (e) {}
  try { terminateProcess(getCurrentProcess(), 0); } catch (e) {}
}
let inCipher = 0;

interface Cand { address: NativePointer; handle: NativePointer; klass: Il2Cpp.Class; className: string; cipherOffset: number; }
interface IncomingCandidateGroup { address: NativePointer; candidates: Cand[]; }
function inModule(address: NativePointer): boolean { const base = Il2Cpp.module.base; return address.compare(base) >= 0 && address.compare(base.add(Il2Cpp.module.size)) < 0; }
function cipherFieldOffset(klass: Il2Cpp.Class, cipherNames: Set<string>): number { for (const field of klass.fields) if (cipherNames.has(field.type.name)) return field.offset; return -1; }
function incomingCandidateId(candidate: Cand): string { return candidate.address + ":" + candidate.handle + ":" + candidate.klass.handle + ":" + candidate.cipherOffset; }
function incomingCandidateForCall(candidates: Cand[], instance: NativePointer, method: NativePointer): Cand | null {
  if (!method.isNull()) {
    const exactMethod = candidates.find(candidate => candidate.handle.equals(method));
    if (exactMethod) return exactMethod;
  }
  let klass: Il2Cpp.Class | null = new Il2Cpp.Object(instance).class;
  while (klass) {
    const exactClass = candidates.find(candidate => candidate.klass.handle.equals(klass!.handle));
    if (exactClass) return exactClass;
    klass = klass.parent;
  }
  return candidates.length === 1 ? candidates[0] : null;
}

function discover() {
  const cipher: Cand[] = [], outAll: Cand[] = [], inAll: Cand[] = [], outSend: Cand[] = [];
  const cipherNames = new Set<string>();
  for (const assembly of Il2Cpp.domain.assemblies) {
    for (const klass of assembly.image.classes) {
      let methods: Il2Cpp.Method[]; try { methods = klass.methods; } catch (e) { continue; }
      for (const method of methods) {
        const returnType = method.returnType.name; const paramCount = method.parameterCount;
        const isByteToByte = returnType === "System.Byte" && paramCount === 1 && method.parameters[0].type.name === "System.Byte";
        if (isByteToByte) cipherNames.add(klass.name);
        if (method.isStatic) continue;
        let address: NativePointer; try { address = method.virtualAddress; } catch (e) { continue; }
        if (address.isNull() || !inModule(address)) continue;
        const cand: Cand = { address, handle: method.handle, klass, className: klass.name, cipherOffset: -1 };
        if (isByteToByte) cipher.push(cand);
        else if (returnType === "System.Byte[]" && paramCount === 0) outAll.push(cand);
        else if (returnType === "System.Void" && paramCount === 3 && method.parameters[0].type.name === "System.Byte[]" && method.parameters[1].type.name === "System.Int32" && method.parameters[2].type.name === "System.Int32") inAll.push(cand);
        else if (returnType === "System.Void" && paramCount === 1 && method.parameters[0].type.name === "System.Byte[]") outSend.push(cand);
      }
    }
  }
  const outCand = outAll.map(cand => { const offset = cipherFieldOffset(cand.klass, cipherNames); if (offset < 0) return null; cand.cipherOffset = offset; return cand; }).filter(Boolean) as Cand[];
  const inCand = inAll.map(cand => { const offset = cipherFieldOffset(cand.klass, cipherNames); if (offset < 0) return null; cand.cipherOffset = offset; return cand; }).filter(Boolean) as Cand[];
  return { cipher, outCand, inCand, outSend, cipherNames };
}

const AGENT_VERSION = "unity-standalone 1.0";
function main(): void {
  log("[agent] " + AGENT_VERSION + " loaded, bridge port " + bridgeport);

  try { const fn = winsock.getExportByName("WSACleanup"); if (fn) Interceptor.attach(fn, { onEnter() { teardown("WSACleanup"); } }); } catch (e) {}
  try { const fn = Il2Cpp.module.getExportByName("il2cpp_shutdown"); if (fn) Interceptor.attach(fn, { onEnter() { teardown("il2cpp_shutdown"); } }); } catch (e) {}

  try {
    const user32 = Module.load("user32.dll");
    ["PeekMessageW", "PeekMessageA"].forEach(name => {
      const fn = user32.findExportByName(name); if (fn) Interceptor.attach(fn, {
        onEnter() {
          if (shuttingDown || injecting || !outThreadId) return;
          if (Process.getCurrentThreadId() !== outThreadId) return;
          if (!instantInject) { instantInject = true; log("[inject] instant path active (per-frame on OUT thread)"); }
          try { pollInjects(); if (injectQueue.length) flushInjects(); if (toClientReady && toClientQueue.length) { let queued: { header: number; body: number[] } | undefined; while ((queued = toClientQueue.shift())) injectToClient(queued.header, queued.body); } } catch (e) { logErr("peek", e); }
        }
      });
    });
  } catch (e) {}

  const discovered = discover();
  byteClass = Il2Cpp.corlib.class("System.Byte");
  toClientByteClass = byteClass;
  log("[disc] cipher=" + discovered.cipher.length + " outCand=" + discovered.outCand.length + " inCand=" + discovered.inCand.length + " outSend=" + discovered.outSend.length);
  const incomingGroupsByAddress = new Map<string, IncomingCandidateGroup>();
  const incomingCandidatesById = new Map<string, Cand>();
  for (const candidate of discovered.inCand) {
    const candidateId = incomingCandidateId(candidate);
    if (incomingCandidatesById.has(candidateId)) continue;
    incomingCandidatesById.set(candidateId, candidate);
    const address = candidate.address.toString();
    const group = incomingGroupsByAddress.get(address);
    if (group) group.candidates.push(candidate);
    else incomingGroupsByAddress.set(address, { address: candidate.address, candidates: [candidate] });
  }
  const configureIncoming = (candidate: Cand): void => {
    const candidateId = incomingCandidateId(candidate);
    if (configuredIncomingId === candidateId && toClientRecv) return;
    configuredIncomingId = null;
    resetToClientBinding();
    if (!setupToClient(candidate)) return;
    configuredIncomingId = candidateId;
    const returnAddress = incomingReturnAddressesById.get(candidateId);
    if (returnAddress) findToClientDispatch(returnAddress, toClientGeneration);
  };
  const publishIncoming = (result: IncomingCoordinatorResult, matchedEngine: NativePointer | null = null): void => {
    if (result.error) logErr("in-frame", result.error);
    if (result.boundChanged && result.boundCandidateId) {
      const candidate = incomingCandidatesById.get(result.boundCandidateId);
      if (candidate) {
        configureIncoming(candidate);
        log("[IN bound] " + candidate.className);
      }
    }
    if (result.cipherMatched && matchedEngine && !inEngine) {
      inEngine = matchedEngine;
      cipherActive = true;
      removeCipherRecords(matchedEngine);
      log("[eng] inEngine locked " + matchedEngine + " tid=" + Process.getCurrentThreadId());
    }
    for (const frame of result.frames) {
      inCount++;
      notify(DIR_TO_CLIENT, frame.bytes);
    }
  };
  const cipherCandidates: Cand[] = [];
  const cipherAddresses = new Set<string>();
  for (const candidate of discovered.cipher) {
    const address = candidate.address.toString();
    if (cipherAddresses.has(address)) continue;
    cipherAddresses.add(address);
    cipherCandidates.push(candidate);
  }
  cipherCandidates.forEach(cand => {
    Interceptor.attach(cand.address, {
      onEnter(args) { (this as any).inputByte = args[1].toInt32() & 0xff; (this as any).engine = args[0]; (this as any).method = args[2].isNull() ? cand.handle : args[2]; },
      onLeave(ret) {
        if (shuttingDown || injecting) return;
        try {
          const input = (this as any).inputByte as number;
          const output = ret.toInt32() & 0xff;
          const engine = (this as any).engine as NativePointer;
          const method = (this as any).method as NativePointer;
          const threadId = Process.getCurrentThreadId();
          const incomingContext = incomingCipherContexts.match(threadId, engine.toString());
          if (incomingContext && !incomingContext.current) return;
          const boundCandidateId = incomingCoordinator.boundCandidateId;
          let incomingCandidateId = incomingContext?.candidateId ?? null;
          if (!incomingContext) {
            const isOutgoingEngine = outEngine !== null && engine.equals(outEngine) && (inEngine === null || !engine.equals(inEngine));
            if (!isOutgoingEngine) {
              if (inEngine === null || engine.equals(inEngine)) {
                incomingCandidateId = incomingCipherContexts.resolveCandidate(engine.toString(), boundCandidateId);
              }
            }
          }
          const allowCrossThread = incomingCandidateId !== null;
          const isKnownInbound = inEngine !== null && engine.equals(inEngine);
          if (!isKnownInbound) recordCipher(input, output, engine, threadId, cand.address, method);
          if (incomingCandidateId) {
            if (inEngine && !engine.equals(inEngine)) return;
            inCipher++;
            publishIncoming(incomingCoordinator.cipher(incomingCandidateId, engine.toString(), threadId, input, output, cand.address + ":" + method, allowCrossThread), engine);
          }
        } catch (e) { logErr("cipher", e); }
      }
    });
  });

  let boundOutSend: NativePointer | null = null;
  const outSendCandidates: Cand[] = [];
  const outSendAddresses = new Set<string>();
  for (const candidate of discovered.outSend) {
    const address = candidate.address.toString();
    if (outSendAddresses.has(address)) continue;
    outSendAddresses.add(address);
    outSendCandidates.push(candidate);
  }
  outSendCandidates.forEach(cand => {
    try {
      Interceptor.attach(cand.address, {
        onEnter(args) {
          if (shuttingDown || injecting) return;
          try {
            if (boundOutSend && !cand.address.equals(boundOutSend)) return;
            const array = args[1]; if (array.isNull()) return;
            const total = array.add(ARRAY_LENGTH_OFFSET).readS32(); if (total < 6 || total > MAX_PACKET_LENGTH) return;
            const declaredLen = (array.add(ARRAY_DATA_OFFSET).readU8() * 0x1000000) + (array.add(ARRAY_DATA_OFFSET + 1).readU8() << 16) + (array.add(ARRAY_DATA_OFFSET + 2).readU8() << 8) + array.add(ARRAY_DATA_OFFSET + 3).readU8();
            if (declaredLen < 2 || declaredLen > MAX_FRAME_LENGTH) return;
            const bytes = readArray(array, 0, 0);
            if (!isHabbo(bytes)) return;
            if (!readyToConnect) { readyToConnect = true; if (gameHost) ensureConnected(); else setTimeout(() => Il2Cpp.perform(() => { captureHostFromMemory(); ensureConnected(); }), 0); }
            if (!boundOutSend) { boundOutSend = cand.address; outSendFn = new NativeFunction(cand.address, "void", ["pointer", "pointer", "pointer"]); log("[OUT bound] " + cand.className + " tid=" + Process.getCurrentThreadId()); }
            outThreadId = Process.getCurrentThreadId();
            outSendThis = args[0]; outSendMethod = args[2];
            if (isHello(bytes)) resetCipherState();
            if (bytes.length < total) { const frames = splitFrames(array, total); if (frames && frames.length > 1) { interceptBatch(array, total, frames, args); return; } }
            outCount++;
            const sendThread = Process.getCurrentThreadId();
            const pair = findCipherPair(bytes[4], bytes[5], sendThread);
            const record4 = pair?.record4 ?? null, record5 = pair?.record5 ?? null;
            let keystream4 = 0, keystream5 = 0, havePlain = false;
            if (record4 && record5 && lockOutCipher(record4)) { keystream4 = bytes[4] ^ record4.input; keystream5 = bytes[5] ^ record5.input; bytes[4] = record4.input; bytes[5] = record5.input; havePlain = true; cipherActive = true; }
            if (debugHeaders) log("[OUT] hdr=" + ((bytes[4] << 8) | bytes[5]) + " matched=" + havePlain + " len=" + total);
            let finalPlain: number[] | null = null;
            if (havePlain && bridgeReady && cipherActive) {
              const verdict = interceptOut(bytes);
              if (verdict) { if (verdict.blocked) { finalPlain = [0, 0, 0, 2, 0, 196]; } else if (verdict.bytes && verdict.bytes.length >= 6 && isHabbo(verdict.bytes) && !sameBytes(verdict.bytes, bytes)) { finalPlain = verdict.bytes.slice(); } }
            } else if (bridgeReady) { if (((bytes[4] << 8) | bytes[5]) <= MAX_HEADER) notify(DIR_TO_SERVER, bytes); }
            // flush injects on the out thread. peekmessage path is just faster when it fires
            let extra: number[] = [];
            if (injectQueue.length && byteClass && outEngine && cipherFn) {
              injecting = true;
              try { let queued: { direction: number; header: number; body: number[] } | undefined; while ((queued = injectQueue.shift())) { if (queued.direction === DIR_TO_SERVER) extra = extra.concat(buildOutPacket(queued.header, queued.body)); else toClientQueue.push({ header: queued.header, body: queued.body }); } } catch (e) { logErr("inject", e); } finally { injecting = false; }
            }
            if (toClientReady && toClientQueue.length) { let queued: { header: number; body: number[] } | undefined; while ((queued = toClientQueue.shift())) injectToClient(queued.header, queued.body); }
            if (finalPlain === null && extra.length === 0) return;
            const originalLength = bytes.length;
            let headBytes: number[];
            if (finalPlain !== null) { headBytes = finalPlain.slice(); if (headBytes.length >= 6) { headBytes[4] ^= keystream4; headBytes[5] ^= keystream5; } }
            else { headBytes = readArray(array, 0, originalLength); }
            const combined = extra.length ? headBytes.concat(extra) : headBytes;
            if (combined.length === total) {
              for (let index = 0; index < combined.length; index++) array.add(ARRAY_DATA_OFFSET + index).writeU8(combined[index]);
            } else { const byteArray = Il2Cpp.array<number>(byteClass!, combined); args[1] = byteArray.handle; }
          } catch (e) {}
        }
      });
    } catch (e) {}
  });

  incomingGroupsByAddress.forEach(group => {
    Interceptor.attach(group.address, {
      onEnter(args) {
        (this as any).incomingCandidateId = null;
        (this as any).incomingFrameIds = [];
        (this as any).incomingPlainEligible = false;
        (this as any).incomingGeneration = 0;
        (this as any).incomingContextThreadId = 0;
        (this as any).incomingContextToken = 0;
        if (shuttingDown || toClientInjecting) return;
        try {
          const cand = incomingCandidateForCall(group.candidates, args[0], args[4]);
          if (!cand) return;
          const candidateId = incomingCandidateId(cand);
          if (incomingCoordinator.boundCandidateId !== null && incomingCoordinator.boundCandidateId !== candidateId) return;
          (this as any).incomingGeneration = cipherGeneration;
          const threadId = Process.getCurrentThreadId();
          const incomingEngine = args[0].add(cand.cipherOffset).readPointer();
          const array = args[1], offset = args[2].toInt32(), length = args[3].toInt32();
          if (array.isNull() || length <= 0) return;
          const returnAddress = (this as any).returnAddress as NativePointer;
          incomingReturnAddressesById.set(candidateId, returnAddress);
          if (configuredIncomingId === candidateId && toClientRecv && !toClientDispatch) findToClientDispatch(returnAddress, toClientGeneration);
          const chunk = readChunk(array, offset, length);
          if (chunk === null) {
            publishIncoming(incomingCoordinator.reject(candidateId, "incoming receive range is invalid"));
            return;
          }
          const result = incomingCoordinator.append(candidateId, threadId, chunk);
          if (result.error) incomingCipherContexts.forgetCandidate(candidateId);
          else if (!incomingEngine.isNull()) {
            incomingCipherContexts.rememberCandidate(candidateId, incomingEngine.toString());
            (this as any).incomingContextThreadId = threadId;
            (this as any).incomingContextToken = incomingCipherContexts.enter(candidateId, incomingEngine.toString(), threadId);
          }
          (this as any).incomingCandidateId = candidateId;
          (this as any).incomingFrameIds = result.completedFrameIds;
          (this as any).incomingPlainEligible = incomingEngine.isNull();
          publishIncoming(result);
        } catch (e) { logErr("inrecv", e); }
      },
      onLeave() {
        const contextThreadId = (this as any).incomingContextThreadId as number;
        const contextToken = (this as any).incomingContextToken as number;
        try {
          if (shuttingDown || !(this as any).incomingPlainEligible) return;
          if ((this as any).incomingGeneration !== cipherGeneration) return;
          const candidateId = (this as any).incomingCandidateId as string | null;
          const frameIds = (this as any).incomingFrameIds as number[];
          if (!candidateId || frameIds.length === 0) return;
          publishIncoming(incomingCoordinator.plain(candidateId, frameIds));
        } finally {
          if (contextToken) incomingCipherContexts.leave(contextThreadId, contextToken);
        }
      }
    });
  });

  ensureConnected();
  every(2000, ensureConnected);
  log("[agent] ready (" + (bridgeReady ? "bridge connected" : "waiting for G-Earth bridge") + ")");

  let lastOut = 0, lastIn = 0;
  every(5000, () => {
    if (shuttingDown) return;
    log("[stat] out=" + outCount + "(+" + (outCount - lastOut) + ") in=" + inCount + "(+" + (inCount - lastIn) + ") inCipher=" + inCipher + " ge=" + (bridgeReady ? 1 : 0) + " cipher=" + (cipherActive ? 1 : 0) + " outEng=" + (outEngine ? 1 : 0) + " inEng=" + (inEngine ? 1 : 0) + " pendIn=" + incomingCoordinator.pendingCount + " injQ=" + injectQueue.length);
    lastOut = outCount; lastIn = inCount;
  });
}

Il2Cpp.perform(() => { setTimeout(() => { try { main(); } catch (e: any) { log("[agent] ERR " + e + "\n" + (e && e.stack)); } }, 800); });
