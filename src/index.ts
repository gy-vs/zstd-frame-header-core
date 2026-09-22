/**
 * Zstandard frame header parsing (RFC 8478, section 3.1.1).
 *
 * Frame header layout:
 *
 *   Frame_Header_Descriptor  (1 byte)
 *   Window_Descriptor        (1 byte, absent when Single_Segment_flag is set)
 *   Dictionary_ID            (0/1/2/4 bytes, per Dictionary_ID_Flag)
 *   Frame_Content_Size       (0/1/2/4/8 bytes, per FCS_flag and Single_Segment_flag)
 *
 * The first block header starts immediately after Frame_Content_Size.
 */

/** Magic_Number of a Zstandard frame (0x184D2204), little-endian bytes 28 B5 2F FD. */
export const ZSTD_MAGIC_NUMBER = 0xfd2fb528;

/** Default maximum back-reference distance accepted by the parser (2 GiB). */
export const DEFAULT_MAX_WINDOW_SIZE = 2 ** 31;

/** Field width of Dictionary_ID for each value of Dictionary_ID_Flag. */
const DICTIONARY_ID_WIDTH = [0, 1, 2, 4] as const;

/** Flags extracted from the Frame_Header_Descriptor byte (RFC 8478 §3.1.1.1). */
export interface FrameHeader {
  /** Single_Segment_flag (bit 5): frame content must fit in memory; no window descriptor. */
  singleSegment: boolean;
  /** Content_Checksum_flag (bit 4): a 4-byte checksum follows the last block. */
  checksum: boolean;
  /** Dictionary_ID_Flag (bits 0-1): field width selector, value 0..3. */
  dictionaryIdFlag: number;
  /** Frame_Content_Size_flag (bits 6-7): field width selector, value 0..3. */
  contentSizeFlag: number;
}

/** Options for {@link parseFrameHeader}. */
export interface ParseFrameHeaderOptions {
  /** Byte offset of the Frame_Header_Descriptor within `data` (default 0). */
  offset?: number;
  /**
   * Largest Window_Size (and, for single-segment frames, content size) accepted
   * in bytes. Defaults to {@link DEFAULT_MAX_WINDOW_SIZE} (2 GiB). Pass
   * `Infinity` to disable the limit. RFC 8478 caps encodable Window_Size at
   * 3.75 TiB.
   */
  maxWindowSize?: number | bigint;
}

/** A fully decoded Zstandard frame header. */
export interface ZstdFrameHeader {
  /** Flags decoded from the descriptor byte. */
  descriptor: FrameHeader;
  /** Raw Window_Descriptor byte, or null for single-segment frames. */
  windowDescriptor: number | null;
  /**
   * Window_Size in bytes. Decoded from Window_Descriptor for regular frames;
   * derived from the content size for single-segment frames. `bigint` only when
   * derived from an 8-byte content size above 2^53.
   */
  windowSize: number | bigint;
  /** Dictionary_ID; 0 when Dictionary_ID_Flag is 0. */
  dictionaryId: number;
  /**
   * Frame content size in bytes: a `number` for values <= 2^53, `bigint` for
   * larger 8-byte values, or `null` when the frame does not carry a content
   * size (non-single-segment frame with FCS_flag 0).
   */
  contentSize: number | bigint | null;
  /** Total length of the frame header in bytes. */
  headerSize: number;
  /** Offset of the first block header, immediately after the frame header. */
  headerEnd: number;
}

export type FrameHeaderErrorCode =
  | 'unexpected-end'
  | 'reserved-bit-set'
  | 'window-too-large'
  | 'invalid-content-size';

/** Error thrown when a frame header violates RFC 8478 or configured limits. */
export class FrameHeaderError extends Error {
  readonly code: FrameHeaderErrorCode;
  /** Name of the truncated field, present when code is 'unexpected-end'. */
  readonly field?: string;

  constructor(code: FrameHeaderErrorCode, message: string, field?: string) {
    super(message);
    this.name = 'FrameHeaderError';
    this.code = code;
    this.field = field;
  }
}

/** Decode the Frame_Header_Descriptor byte (RFC 8478 §3.1.1.1). */
export function parseDescriptor(byte: number): FrameHeader {
  return {
    contentSizeFlag: byte >> 6, // bits 7-6
    dictionaryIdFlag: byte & 3, // bits 1-0
    checksum: (byte & 0x10) !== 0, // bit 4: Content_Checksum_flag
    singleSegment: (byte & 0x20) !== 0, // bit 5: Single_Segment_flag
  };
}

/**
 * Width in bytes of the Frame_Content_Size field.
 *
 * Multi-segment frames: FCS_flag 0/1/2/3 -> 0/2/4/8 bytes.
 * Single-segment frames: FCS_flag 0/1/2/3 -> 1/2/2/4 bytes (never 0).
 */
export function frameContentSizeFieldSize(descriptor: FrameHeader): number {
  const fcsFlag = descriptor.contentSizeFlag;
  if (descriptor.singleSegment) {
    if (fcsFlag === 0) return 1;
    if (fcsFlag === 3) return 4;
    return 2;
  }
  if (fcsFlag === 0) return 0;
  if (fcsFlag === 1) return 2;
  if (fcsFlag === 2) return 4;
  return 8;
}

/** Width in bytes of the Dictionary_ID field (0, 1, 2 or 4). */
export function dictionaryIdFieldSize(dictionaryIdFlag: number): number {
  return DICTIONARY_ID_WIDTH[dictionaryIdFlag];
}

function requireBytes(
  data: Uint8Array,
  pos: number,
  width: number,
  field: string,
): void {
  if (pos < 0 || pos + width > data.length) {
    throw new FrameHeaderError(
      'unexpected-end',
      `truncated frame header: ${field} needs ${width} byte(s) at offset ${pos}, got ${Math.max(0, data.length - pos)}`,
      field,
    );
  }
}

function readUnsignedLE(
  data: Uint8Array,
  pos: number,
  width: number,
  field: string,
): number | bigint {
  requireBytes(data, pos, width, field);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (width === 1) return view.getUint8(pos);
  if (width === 2) return view.getUint16(pos, true);
  if (width === 4) return view.getUint32(pos, true);
  return view.getBigUint64(pos, true);
}

/** Decode a Window_Descriptor byte (RFC 8478 §3.1.1.2). */
export function decodeWindowSize(windowDescriptor: number): number {
  const exponent = windowDescriptor >> 3; // bits 7-3
  const mantissa = windowDescriptor & 7; // bits 2-0
  return 2 ** exponent * (1024 + 128 * mantissa);
}

function normalizeContentSize(raw: number | bigint): number | bigint {
  return typeof raw === 'bigint'
    ? raw <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(raw)
      : raw
    : raw;
}

/**
 * Parse a Zstandard frame header starting at the Frame_Header_Descriptor byte.
 *
 * @throws {FrameHeaderError} on truncation, reserved descriptor bits, content
 *         sizes that exceed `maxWindowSize`, window sizes that exceed the
 *         configured limit, or invalid Frame_Content_Size encodings.
 */
export function parseFrameHeader(
  data: Uint8Array,
  options: ParseFrameHeaderOptions = {},
): ZstdFrameHeader {
  const start = options.offset ?? 0;
  const maxWindowSize =
    options.maxWindowSize === undefined
      ? BigInt(DEFAULT_MAX_WINDOW_SIZE)
      : options.maxWindowSize === Infinity
        ? null
        : BigInt(options.maxWindowSize);

  let pos = start;

  // Frame_Header_Descriptor (1 byte).
  requireBytes(data, pos, 1, 'descriptor');
  const descriptorByte = data[pos]!;
  pos += 1;

  // Bits 3-2 are reserved and must be zero.
  if (descriptorByte & 0x0c) {
    throw new FrameHeaderError(
      'reserved-bit-set',
      `reserved bits set in frame header descriptor: 0x${descriptorByte.toString(16).padStart(2, '0')}`,
    );
  }

  const descriptor = parseDescriptor(descriptorByte);

  // Window_Descriptor is present exactly when Single_Segment_flag == 0.
  let windowDescriptor: number | null = null;
  let windowSize: number | bigint;
  if (!descriptor.singleSegment) {
    requireBytes(data, pos, 1, 'windowDescriptor');
    windowDescriptor = data[pos]!;
    pos += 1;
    windowSize = decodeWindowSize(windowDescriptor);
    if (maxWindowSize !== null && BigInt(windowSize) > maxWindowSize) {
      throw new FrameHeaderError(
        'window-too-large',
        `window size ${windowSize} exceeds configured maximum ${maxWindowSize}`,
      );
    }
  } else {
    // Derived from Frame_Content_Size below.
    windowSize = 0;
  }

  // Dictionary_ID (0/1/2/4 bytes).
  const dictIdWidth = dictionaryIdFieldSize(descriptor.dictionaryIdFlag);
  let dictionaryId = 0;
  if (dictIdWidth > 0) {
    dictionaryId = readUnsignedLE(
      data,
      pos,
      dictIdWidth,
      'dictionaryId',
    ) as number;
    pos += dictIdWidth;
  }

  // Frame_Content_Size (0/1/2/4/8 bytes).
  const fcsWidth = frameContentSizeFieldSize(descriptor);
  let contentSize: number | bigint | null = null;
  if (fcsWidth > 0) {
    const raw = readUnsignedLE(data, pos, fcsWidth, 'contentSize');
    pos += fcsWidth;
    if (fcsWidth === 1 || fcsWidth === 2) {
      // 1 byte: direct 0..255; 2 bytes: direct value + 256.
      contentSize = (raw as number) + (fcsWidth === 2 ? 256 : 0);
    } else if (fcsWidth === 4) {
      // 4 bytes: direct 256..2^32-1; values 0..255 are invalid.
      if ((raw as number) < 256) {
        throw new FrameHeaderError(
          'invalid-content-size',
          `4-byte frame content size field value ${raw} is invalid (must be >= 256)`,
        );
      }
      contentSize = raw as number;
    } else {
      // 8 bytes: direct 0..2^64-1.
      contentSize = normalizeContentSize(raw);
    }
  }

  // Single-segment frames derive Window_Size from the content size.
  if (descriptor.singleSegment) {
    windowSize = contentSize as number | bigint;
    if (maxWindowSize !== null && BigInt(windowSize) > maxWindowSize) {
      throw new FrameHeaderError(
        'window-too-large',
        `single-segment content size ${windowSize} exceeds configured maximum window ${maxWindowSize}`,
      );
    }
  }

  return {
    descriptor,
    windowDescriptor,
    windowSize,
    dictionaryId,
    contentSize,
    headerSize: pos - start,
    // Points at the first block header.
    headerEnd: pos,
  };
}

/** Parse a 3-byte block header (RFC 8478 §3.1.1.3). Returns null when truncated. */
export function readBlockHeader(data: Uint8Array): {
  last: boolean;
  type: number;
  size: number;
} | null {
  if (data.length < 3) return null;
  const value = data[0]! | (data[1]! << 8) | (data[2]! << 16);
  return { last: Boolean(value & 1), type: (value >> 1) & 3, size: value >> 3 };
}
