export const ZSTD_MAGIC_NUMBER = 0xfd2fb528;

const ZSTD_MAGIC_BYTES = [0x28, 0xb5, 0x2f, 0xfd] as const;
const DICTIONARY_ID_FIELD_SIZE = [0, 1, 2, 4] as const;
const CONTENT_SIZE_FIELD_SIZE = [
  [0, 2, 4, 8],
  [1, 2, 4, 4],
] as const;
const RESERVED_BIT = 0x08;

export interface FrameHeader {
  singleSegment: boolean;
  checksum: boolean;
  dictionaryIdFlag: number;
  contentSizeFlag: number;
}

export interface ParseOptions {
  offset?: number;
  maxWindowSize?: number | bigint;
}

export interface ParsedFrameHeader extends FrameHeader {
  magicNumber: number;
  descriptor: number;
  windowDescriptor: number | null;
  windowSize: number | bigint;
  dictionaryIdFieldSize: number;
  dictionaryId: number | null;
  dictionaryIdPresent: boolean;
  hasDictionaryId: boolean;
  contentSizeFieldSize: number;
  contentSize: number | bigint | null;
  contentSizePresent: boolean;
  hasContentSize: boolean;
  hasChecksum: boolean;
  frameHeaderSize: number;
  headerSize: number;
  offset: number;
  endOffset: number;
  blockHeaderOffset: number;
}

export type FrameHeaderFields = Omit<
  ParsedFrameHeader,
  'magicNumber' | 'offset' | 'headerSize'
>;

export function parseDescriptor(byte: number): FrameHeader {
  return {
    contentSizeFlag: byte >> 6,
    dictionaryIdFlag: byte & 3,
    checksum: Boolean(byte & 4),
    singleSegment: Boolean(byte & 32),
  };
}

export function readBlockHeader(data: Uint8Array) {
  if (data.length < 3) return null;
  const value = data[0] | (data[1] << 8) | (data[2] << 16);
  return {
    last: Boolean(value & 1),
    type: (value >> 1) & 3,
    size: value >> 3,
  };
}

export function parseFrameHeader(
  data: Uint8Array,
  options: ParseOptions = {},
): ParsedFrameHeader {
  const start = normalizeOffset(options.offset, data);
  requireBytes(data, start, 4, 'magic number');

  for (let i = 0; i < 4; i++) {
    if (data[start + i] !== ZSTD_MAGIC_BYTES[i]) {
      throw new Error('Invalid Zstandard frame magic number');
    }
  }

  const fields = parseFrameHeaderFields(data, {
    offset: start + 4,
    maxWindowSize: options.maxWindowSize,
  });
  const endOffset = fields.endOffset;

  return {
    ...fields,
    magicNumber: ZSTD_MAGIC_NUMBER,
    offset: start,
    endOffset,
    blockHeaderOffset: endOffset,
    headerSize: endOffset - start,
  };
}

export function parseFrameHeaderFields(
  data: Uint8Array,
  optionsOrOffset: ParseOptions | number = {},
): FrameHeaderFields {
  const options =
    typeof optionsOrOffset === 'number'
      ? {offset: optionsOrOffset}
      : optionsOrOffset;
  const start = normalizeOffset(options.offset, data);
  const maxWindowSize = normalizeMaxWindowSize(options.maxWindowSize);

  requireBytes(data, start, 1, 'frame header descriptor');
  const descriptor = data[start];
  if (descriptor & RESERVED_BIT) {
    throw new Error('Frame header descriptor reserved bit must be zero');
  }

  const flags = parseDescriptor(descriptor);
  let position = start + 1;
  let windowDescriptor: number | null = null;
  let windowSize: number | bigint;

  if (!flags.singleSegment) {
    requireBytes(data, position, 1, 'window descriptor');
    windowDescriptor = data[position];
    position++;

    const exponent = windowDescriptor >> 3;
    if (exponent > 21) {
      throw new RangeError(
        `Window descriptor exponent ${exponent} exceeds the RFC-defined maximum 21`,
      );
    }

    const mantissa = BigInt(windowDescriptor & 7);
    const windowBase = 1n << BigInt(exponent + 10);
    const size = windowBase + (windowBase >> 3n) * mantissa;
    windowSize = toNumberOrBigInt(size);
    ensureWithinConfiguredWindow(size, maxWindowSize);
  }

  const dictionaryIdFieldSize =
    DICTIONARY_ID_FIELD_SIZE[flags.dictionaryIdFlag];
  requireBytes(data, position, dictionaryIdFieldSize, 'dictionary ID');
  const dictionaryIdRaw = readUnsignedLE(
    data,
    position,
    dictionaryIdFieldSize,
  );
  const dictionaryId =
    dictionaryIdFieldSize === 0 ? null : Number(dictionaryIdRaw);
  position += dictionaryIdFieldSize;

  const contentSizeFieldSize =
    CONTENT_SIZE_FIELD_SIZE[flags.singleSegment ? 1 : 0][
      flags.contentSizeFlag
    ];
  requireBytes(data, position, contentSizeFieldSize, 'frame content size');
  let contentSize: number | bigint | null = null;
  if (contentSizeFieldSize > 0) {
    const rawSize = readUnsignedLE(
      data,
      position,
      contentSizeFieldSize,
    );
    const uses256Offset = contentSizeFieldSize === 2;
    contentSize = toNumberOrBigInt(rawSize + (uses256Offset ? 256n : 0n));
  }
  position += contentSizeFieldSize;

  if (flags.singleSegment) {
    windowSize = contentSize as number | bigint;
    ensureWithinConfiguredWindow(
      typeof windowSize === 'bigint' ? windowSize : BigInt(windowSize),
      maxWindowSize,
    );
  }

  const frameHeaderSize = position - start;
  const contentSizePresent = contentSizeFieldSize > 0;
  const dictionaryIdPresent = dictionaryIdFieldSize > 0;

  return {
    ...flags,
    descriptor,
    windowDescriptor,
    windowSize: windowSize!,
    dictionaryIdFieldSize,
    dictionaryId,
    dictionaryIdPresent,
    hasDictionaryId: dictionaryIdPresent,
    contentSizeFieldSize,
    contentSize,
    contentSizePresent,
    hasContentSize: contentSizePresent,
    hasChecksum: flags.checksum,
    frameHeaderSize,
    endOffset: position,
    blockHeaderOffset: position,
  };
}

function requireBytes(
  data: Uint8Array,
  offset: number,
  length: number,
  fieldName: string,
): void {
  if (length === 0) return;
  if (offset < 0 || offset + length > data.length) {
    throw new RangeError(
      `Truncated frame header: expected ${length} byte${
        length === 1 ? '' : 's'
      } for ${fieldName} at offset ${offset}`,
    );
  }
}

function readUnsignedLE(
  data: Uint8Array,
  offset: number,
  length: number,
): bigint {
  let value = 0n;
  for (let i = length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(data[offset + i]);
  }
  return value;
}

function normalizeOffset(offset: number | undefined, data: Uint8Array): number {
  const value = offset ?? 0;
  if (!Number.isInteger(value) || value < 0 || value > data.length) {
    throw new RangeError(`Invalid offset: ${offset}`);
  }
  return value;
}

function normalizeMaxWindowSize(
  value: number | bigint | undefined,
): bigint | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new RangeError(`Invalid maxWindowSize: ${value}`);
    }
    return BigInt(value);
  }
  if (value < 0n) {
    throw new RangeError(`Invalid maxWindowSize: ${value}`);
  }
  return value;
}

function ensureWithinConfiguredWindow(
  windowSize: bigint,
  maxWindowSize: bigint | undefined,
): void {
  if (maxWindowSize !== undefined && windowSize > maxWindowSize) {
    throw new RangeError(
      `Window size ${windowSize} exceeds configured maximum ${maxWindowSize}`,
    );
  }
}

function toNumberOrBigInt(value: bigint): number | bigint {
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
}
