export const UNITY_HEADER_LIMIT = 6000;

export interface IncomingFrameStart {
  id: number;
  cipher4: number;
  cipher5: number;
}
export interface IncomingFrame {
  id: number;
  bytes: number[];
}

export interface IncomingStreamResult {
  starts: IncomingFrameStart[];
  frames: IncomingFrame[];
  error: string | null;
}

export interface IncomingReadyFrame {
  candidateId: string;
  frameId: number;
  bytes: number[];
}

export interface IncomingCoordinatorResult {
  frames: IncomingReadyFrame[];
  completedFrameIds: number[];
  boundCandidateId: string | null;
  boundChanged: boolean;
  cipherMatched: boolean;
  error: string | null;
}

interface PendingFrame {
  candidateId: string;
  frameId: number;
  threadId: number;
  cipher4: number;
  cipher5: number;
  plain4: number | null;
  plain5: number | null;
  bytes: number[] | null;
}

interface CipherHalf {
  input: number;
  plain: number;
}

type CipherOrder = "fifth-first" | "fourth-first";

interface CipherContext {
  token: number;
  candidateId: string;
  engineId: string;
  generation: number;
}

export interface IncomingCipherContextMatch {
  candidateId: string;
  current: boolean;
}

export class IncomingCipherContexts {
  private readonly contexts = new Map<number, CipherContext[]>();
  private readonly candidatesByEngine = new Map<string, Set<string>>();
  private nextToken = 1;
  private generation = 1;

  rememberCandidate(candidateId: string, engineId: string): void {
    const candidates = this.candidatesByEngine.get(engineId);
    if (candidates) candidates.add(candidateId);
    else this.candidatesByEngine.set(engineId, new Set([candidateId]));
  }

  forgetCandidate(candidateId: string): void {
    for (const [engineId, candidates] of this.candidatesByEngine) {
      candidates.delete(candidateId);
      if (candidates.size === 0) this.candidatesByEngine.delete(engineId);
    }
  }

  resolveCandidate(engineId: string, preferredCandidateId: string | null = null): string | null {
    const candidates = this.candidatesByEngine.get(engineId);
    if (!candidates || candidates.size === 0) return null;
    if (preferredCandidateId && candidates.has(preferredCandidateId)) return preferredCandidateId;
    if (candidates.size !== 1) return null;
    return candidates.values().next().value ?? null;
  }

  enter(candidateId: string, engineId: string, threadId: number): number {
    const token = this.nextToken++;
    const stack = this.contexts.get(threadId);
    const context = { token, candidateId, engineId, generation: this.generation };
    if (stack) stack.push(context);
    else this.contexts.set(threadId, [context]);
    return token;
  }

  match(threadId: number, engineId: string): IncomingCipherContextMatch | null {
    const stack = this.contexts.get(threadId);
    if (!stack) return null;
    for (let index = stack.length - 1; index >= 0; index--) {
      if (stack[index].engineId === engineId) return { candidateId: stack[index].candidateId, current: stack[index].generation === this.generation };
    }
    return null;
  }

  leave(threadId: number, token: number): void {
    const stack = this.contexts.get(threadId);
    if (!stack) return;
    const index = stack.findIndex(context => context.token === token);
    if (index >= 0) stack.splice(index, 1);
    if (stack.length === 0) this.contexts.delete(threadId);
  }

  reset(): void {
    this.generation++;
    this.candidatesByEngine.clear();
  }
}

export class IncomingFrameStream {
  private readonly maximumFrameLength: number;
  private readonly maximumBufferedLength: number;
  private buffer: number[] = [];
  private position = 0;
  private expectedLength: number | null = null;
  private activeId: number | null = null;
  private announced = false;
  private nextId = 1;
  private failed = false;

  constructor(maximumFrameLength: number) {
    if (!Number.isInteger(maximumFrameLength) || maximumFrameLength < 2) throw new RangeError("maximumFrameLength");
    this.maximumFrameLength = maximumFrameLength;
    this.maximumBufferedLength = (maximumFrameLength + 4) * 2;
  }

  append(chunk: readonly number[]): IncomingStreamResult {
    const result: IncomingStreamResult = { starts: [], frames: [], error: null };
    if (this.failed || chunk.length === 0) return result;
    if (chunk.length > this.maximumBufferedLength || this.buffer.length - this.position + chunk.length > this.maximumBufferedLength) {
      return this.fail(result, "incoming frame buffer exceeds limit");
    }

    for (let index = 0; index < chunk.length; index++) this.buffer.push(chunk[index] & 0xff);

    while (true) {
      const available = this.buffer.length - this.position;
      if (this.expectedLength === null) {
        if (available < 4) break;

        const declaredLength =
          this.buffer[this.position] * 0x1000000 +
          this.buffer[this.position + 1] * 0x10000 +
          this.buffer[this.position + 2] * 0x100 +
          this.buffer[this.position + 3];

        if (declaredLength < 2 || declaredLength > this.maximumFrameLength) {
          return this.fail(result, "invalid incoming frame length " + declaredLength);
        }

        this.expectedLength = declaredLength + 4;
        this.activeId = this.nextId++;
        this.announced = false;
      }

      if (!this.announced && available >= 6) {
        result.starts.push({
          id: this.activeId!,
          cipher4: this.buffer[this.position + 4],
          cipher5: this.buffer[this.position + 5],
        });
        this.announced = true;
      }

      if (available < this.expectedLength) break;

      result.frames.push({
        id: this.activeId!,
        bytes: this.buffer.slice(this.position, this.position + this.expectedLength),
      });
      this.position += this.expectedLength;
      this.expectedLength = null;
      this.activeId = null;
      this.announced = false;
    }

    this.compact();
    return result;
  }

  reset(): void {
    this.buffer = [];
    this.position = 0;
    this.expectedLength = null;
    this.activeId = null;
    this.announced = false;
    this.nextId = 1;
    this.failed = false;
  }

  private fail(result: IncomingStreamResult, error: string): IncomingStreamResult {
    this.failed = true;
    this.buffer = [];
    this.position = 0;
    this.expectedLength = null;
    this.activeId = null;
    this.announced = false;
    result.error = error;
    return result;
  }

  private compact(): void {
    if (this.position === 0) return;
    if (this.position === this.buffer.length) {
      this.buffer = [];
      this.position = 0;
      return;
    }
    if (this.position >= 65536 || this.position * 2 >= this.buffer.length) {
      this.buffer = this.buffer.slice(this.position);
      this.position = 0;
    }
  }
}

export class IncomingFrameCoordinator {
  private readonly maximumFrameLength: number;
  private readonly maximumPlainHeader: number;
  private readonly maximumCipherHeader: number;
  private readonly maximumPendingFrames: number;
  private readonly maximumPendingBytes: number;
  private readonly streams = new Map<string, IncomingFrameStream>();
  private readonly failedCandidates = new Set<string>();
  private readonly cipherHalves = new Map<string, CipherHalf>();
  private readonly cipherOrders = new Map<string, CipherOrder>();
  private pending: PendingFrame[] = [];
  private pendingBytes = 0;
  private bound: string | null = null;

  constructor(maximumFrameLength: number, maximumPlainHeader: number, maximumCipherHeader: number, maximumPendingFrames = 4096, maximumPendingBytes = (maximumFrameLength + 4) * 2) {
    if (!Number.isInteger(maximumPlainHeader) || maximumPlainHeader < 0) throw new RangeError("maximumPlainHeader");
    if (!Number.isInteger(maximumCipherHeader) || maximumCipherHeader < maximumPlainHeader) throw new RangeError("maximumCipherHeader");
    if (!Number.isInteger(maximumPendingFrames) || maximumPendingFrames < 1) throw new RangeError("maximumPendingFrames");
    if (!Number.isInteger(maximumPendingBytes) || maximumPendingBytes < 1) throw new RangeError("maximumPendingBytes");
    this.maximumFrameLength = maximumFrameLength;
    this.maximumPlainHeader = maximumPlainHeader;
    this.maximumCipherHeader = maximumCipherHeader;
    this.maximumPendingFrames = maximumPendingFrames;
    this.maximumPendingBytes = maximumPendingBytes;
  }

  get boundCandidateId(): string | null {
    return this.bound;
  }

  get pendingCount(): number {
    return this.pending.length;
  }

  get pendingByteCount(): number {
    return this.pendingBytes;
  }

  append(candidateId: string, threadId: number, chunk: readonly number[]): IncomingCoordinatorResult {
    const result = this.result();
    if (!candidateId || this.failedCandidates.has(candidateId) || this.bound !== null && this.bound !== candidateId) return result;

    let stream = this.streams.get(candidateId);
    if (!stream) {
      stream = new IncomingFrameStream(this.maximumFrameLength);
      this.streams.set(candidateId, stream);
    }

    const parsed = stream.append(chunk);
    if (parsed.error) {
      this.failCandidate(candidateId);
      result.error = parsed.error;
      return result;
    }

    for (const start of parsed.starts) {
      this.pending.push({
        candidateId,
        frameId: start.id,
        threadId,
        cipher4: start.cipher4,
        cipher5: start.cipher5,
        plain4: null,
        plain5: null,
        bytes: null,
      });
    }

    if (this.pending.length > this.maximumPendingFrames) {
      this.failCandidate(candidateId);
      result.error = "incoming frame state exceeds limit";
      return result;
    }

    const completedBytes = parsed.frames.reduce((total, frame) => total + frame.bytes.length, 0);
    if (this.pendingBytes + completedBytes > this.maximumPendingBytes) {
      this.failCandidate(candidateId);
      result.error = "incoming frame payload state exceeds limit";
      return result;
    }

    for (const frame of parsed.frames) {
      const entry = this.pending.find(candidate => candidate.candidateId === candidateId && candidate.frameId === frame.id);
      if (!entry) {
        this.failCandidate(candidateId);
        result.error = "completed incoming frame has no registered header";
        return result;
      }
      if (entry.plain4 === null && entry.plain5 === null) entry.threadId = threadId;
      entry.bytes = frame.bytes;
      this.pendingBytes += frame.bytes.length;
      result.completedFrameIds.push(frame.id);
      const ready = this.takeReady(entry);
      if (ready) result.frames.push(ready);
    }

    result.boundCandidateId = this.bound;
    return result;
  }

  cipher(candidateId: string, engineId: string, threadId: number, input: number, plain: number, methodId = "default", allowCrossThread = false): IncomingCoordinatorResult {
    const result = this.result();
    if (this.failedCandidates.has(candidateId) || this.bound !== null && this.bound !== candidateId) return result;
    this.matchCipher(candidateId, engineId, methodId, threadId, input, plain, allowCrossThread, result);
    return result;
  }

  private matchCipher(candidateId: string, engineId: string, methodId: string, threadId: number, input: number, plain: number, allowCrossThread: boolean, result: IncomingCoordinatorResult): boolean {
    const halfKey = candidateId + ":" + engineId + ":" + methodId + ":" + threadId;
    const candidates = this.pending.filter(entry => entry.candidateId === candidateId && (allowCrossThread || entry.threadId === threadId) && entry.plain4 === null && entry.plain5 === null);
    if (candidates.length === 0) {
      this.cipherHalves.delete(halfKey);
      return false;
    }

    const current = { input: input & 0xff, plain: plain & 0xff };
    const previous = this.cipherHalves.get(halfKey);
    if (!previous) {
      this.cipherHalves.set(halfKey, current);
      return false;
    }

    for (const entry of candidates) {
      const fifthFirst = entry.cipher5 === previous.input && entry.cipher4 === current.input;
      const fourthFirst = entry.cipher4 === previous.input && entry.cipher5 === current.input;
      if (!fifthFirst && !fourthFirst) continue;

      const orderKey = candidateId + ":" + engineId + ":" + methodId;
      const order = fifthFirst && fourthFirst ? this.cipherOrders.get(orderKey) ?? "fifth-first" : fifthFirst ? "fifth-first" : "fourth-first";
      const plain4 = order === "fifth-first" ? current.plain : previous.plain;
      const plain5 = order === "fifth-first" ? previous.plain : current.plain;

      const header = plain4 * 0x100 + plain5;
      if (header >= this.maximumCipherHeader) continue;
      this.cipherOrders.set(orderKey, order);
      entry.plain4 = plain4;
      entry.plain5 = plain5;
      result.boundChanged = this.bind(entry.candidateId);
      result.boundCandidateId = this.bound;
      result.cipherMatched = true;
      this.cipherHalves.delete(halfKey);
      const ready = this.takeReady(entry);
      if (ready) result.frames.push(ready);
      return true;
    }

    this.cipherHalves.set(halfKey, current);
    return false;
  }

  plain(candidateId: string, frameIds: readonly number[]): IncomingCoordinatorResult {
    const result = this.result();
    if (this.failedCandidates.has(candidateId) || this.bound !== null && this.bound !== candidateId) return result;

    for (const frameId of frameIds) {
      const entry = this.pending.find(candidate => candidate.candidateId === candidateId && candidate.frameId === frameId);
      if (!entry || entry.bytes === null || entry.plain4 !== null || entry.plain5 !== null) continue;
      const header = entry.bytes[4] * 0x100 + entry.bytes[5];
      if (header > this.maximumPlainHeader) {
        this.failCandidate(candidateId);
        result.error = "invalid plaintext incoming header " + header;
        return result;
      }
      entry.plain4 = entry.bytes[4];
      entry.plain5 = entry.bytes[5];
      result.boundChanged = this.bind(candidateId) || result.boundChanged;
      result.boundCandidateId = this.bound;
      const ready = this.takeReady(entry);
      if (ready) result.frames.push(ready);
    }

    return result;
  }

  reject(candidateId: string, error: string): IncomingCoordinatorResult {
    const result = this.result();
    if (!this.failedCandidates.has(candidateId) && (this.bound === null || this.bound === candidateId)) {
      this.failCandidate(candidateId);
      result.error = error;
    }
    return result;
  }

  reset(): void {
    this.streams.clear();
    this.failedCandidates.clear();
    this.cipherHalves.clear();
    this.cipherOrders.clear();
    this.pending = [];
    this.pendingBytes = 0;
    this.bound = null;
  }

  private result(): IncomingCoordinatorResult {
    return {
      frames: [],
      completedFrameIds: [],
      boundCandidateId: this.bound,
      boundChanged: false,
      cipherMatched: false,
      error: null,
    };
  }

  private bind(candidateId: string): boolean {
    if (this.bound !== null) return false;
    this.bound = candidateId;
    for (const entry of this.pending) if (entry.candidateId !== candidateId && entry.bytes !== null) this.pendingBytes -= entry.bytes.length;
    this.pending = this.pending.filter(entry => entry.candidateId === candidateId);
    for (const streamId of this.streams.keys()) if (streamId !== candidateId) this.streams.delete(streamId);
    for (const failedId of this.failedCandidates) if (failedId !== candidateId) this.failedCandidates.delete(failedId);
    this.cipherHalves.clear();
    for (const key of this.cipherOrders.keys()) if (!key.startsWith(candidateId + ":")) this.cipherOrders.delete(key);
    return true;
  }

  private takeReady(entry: PendingFrame): IncomingReadyFrame | null {
    if (entry.bytes === null || entry.plain4 === null || entry.plain5 === null) return null;
    const index = this.pending.indexOf(entry);
    if (index < 0) return null;
    this.pending.splice(index, 1);
    this.pendingBytes -= entry.bytes.length;
    entry.bytes[4] = entry.plain4;
    entry.bytes[5] = entry.plain5;
    return { candidateId: entry.candidateId, frameId: entry.frameId, bytes: entry.bytes };
  }

  private failCandidate(candidateId: string): void {
    this.failedCandidates.add(candidateId);
    this.streams.delete(candidateId);
    for (const entry of this.pending) if (entry.candidateId === candidateId && entry.bytes !== null) this.pendingBytes -= entry.bytes.length;
    this.pending = this.pending.filter(entry => entry.candidateId !== candidateId);
    this.clearCipherState(candidateId);
  }

  private clearCipherState(candidateId: string): void {
    for (const key of this.cipherHalves.keys()) if (key.startsWith(candidateId + ":")) this.cipherHalves.delete(key);
    for (const key of this.cipherOrders.keys()) if (key.startsWith(candidateId + ":")) this.cipherOrders.delete(key);
  }
}
