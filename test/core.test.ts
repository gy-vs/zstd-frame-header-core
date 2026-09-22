import { expect, it } from 'vitest';
import {
  DEFAULT_MAX_WINDOW_SIZE,
  FrameHeaderError,
  ZSTD_MAGIC_NUMBER,
  decodeWindowSize,
  frameContentSizeFieldSize,
  parseDescriptor,
  parseFrameHeader,
  readBlockHeader,
} from '../src/index.js';

/** Width of Dictionary_ID for each Dictionary_ID_Flag. */
const DICT_WIDTH = [0, 1, 2, 4] as const;

function leBytes(value: number | bigint, width: number): number[] {
  const out: number[] = [];
  let v = typeof value === 'bigint' ? value : BigInt(value);
  for (let i = 0; i < width; i++) {
    out.push(Number(v & 0xffn));
    v >>= 8n;
  }
  return out;
}

interface MakeHeaderOptions {
  descriptor: number;
  /** Raw Window_Descriptor byte (multi-segment frames only). */
  window?: number;
  /** Raw Dictionary_ID value; width derives from descriptor bits 0-1. */
  dictId?: number;
  /** Raw Frame_Content_Size field value; width derives from FCS flag / single segment. */
  fcs?: number | bigint;
  /** Extra trailing bytes (representing the first block header). */
  trailer?: number[];
}

/** Assemble a frame header in exact RFC 8478 field order. */
function makeHeader(opts: MakeHeaderOptions): Uint8Array {
  const descriptor = parseDescriptor(opts.descriptor);
  const bytes: number[] = [opts.descriptor];
  if (!descriptor.singleSegment) bytes.push(opts.window ?? 0);
  const dictWidth = DICT_WIDTH[descriptor.dictionaryIdFlag];
  if (dictWidth > 0) {
    expect(opts.dictId).toBeDefined();
    bytes.push(...leBytes(opts.dictId!, dictWidth));
  }
  const fcsWidth = frameContentSizeFieldSize(descriptor);
  if (fcsWidth > 0) {
    expect(opts.fcs).toBeDefined();
    bytes.push(...leBytes(opts.fcs!, fcsWidth));
  }
  if (opts.trailer) bytes.push(...opts.trailer);
  return Uint8Array.from(bytes);
}

/** Window_Descriptor byte for the (exponent, mantissa) pair of a window size. */
function windowByte(exponent: number, mantissa: number): number {
  return (exponent << 3) | (mantissa & 7);
}

const U32_MAX = 0xffffffff;

// ---------------------------------------------------------------------------
// parseDescriptor: bit-level decoding
// ---------------------------------------------------------------------------

it('descriptor: zero byte decodes all flags off', () => {
  expect(parseDescriptor(0x00)).toEqual({
    contentSizeFlag: 0,
    dictionaryIdFlag: 0,
    checksum: false,
    singleSegment: false,
  });
});

it('descriptor: FCS flag occupies bits 7-6', () => {
  expect(parseDescriptor(0x40).contentSizeFlag).toBe(1);
  expect(parseDescriptor(0x80).contentSizeFlag).toBe(2);
  expect(parseDescriptor(0xc0).contentSizeFlag).toBe(3);
});

it('descriptor: dictionary id flag occupies bits 1-0', () => {
  expect(parseDescriptor(0x01).dictionaryIdFlag).toBe(1);
  expect(parseDescriptor(0x02).dictionaryIdFlag).toBe(2);
  expect(parseDescriptor(0x03).dictionaryIdFlag).toBe(3);
});

it('descriptor: checksum occupies bit 4 (0x10), not reserved bit 2', () => {
  expect(parseDescriptor(0x10).checksum).toBe(true);
  expect(parseDescriptor(0x04).checksum).toBe(false);
  expect(parseDescriptor(0xff).checksum).toBe(true);
});

it('descriptor: single segment occupies bit 5 (0x20)', () => {
  expect(parseDescriptor(0x20).singleSegment).toBe(true);
  expect(parseDescriptor(0x10).singleSegment).toBe(false);
});

// ---------------------------------------------------------------------------
// Frame_Content_Size: every content size flag, multi-segment frames
// ---------------------------------------------------------------------------

it('fcs flag 0 on multi-segment frame: no content size field, size unknown', () => {
  const header = parseFrameHeader(makeHeader({ descriptor: 0x00, window: 0 }));
  expect(header.contentSize).toBeNull();
  expect(header.descriptor.contentSizeFlag).toBe(0);
  expect(header.headerSize).toBe(2);
});

it('fcs flag 1: 2-byte field, offset 256, range 256..65791', () => {
  let header = parseFrameHeader(makeHeader({ descriptor: 0x40, window: 0, fcs: 0 }));
  expect(frameContentSizeFieldSize(header.descriptor)).toBe(2);
  expect(header.contentSize).toBe(256);
  expect(header.headerSize).toBe(4);

  header = parseFrameHeader(makeHeader({ descriptor: 0x40, window: 0, fcs: 100 }));
  expect(header.contentSize).toBe(356);

  header = parseFrameHeader(makeHeader({ descriptor: 0x40, window: 0, fcs: 65535 }));
  expect(header.contentSize).toBe(65791);
});

it('fcs flag 2: 4-byte field, direct value, range 256..2^32-1', () => {
  let header = parseFrameHeader(makeHeader({ descriptor: 0x80, window: 0, fcs: 256 }));
  expect(frameContentSizeFieldSize(header.descriptor)).toBe(4);
  expect(header.contentSize).toBe(256);
  expect(header.headerSize).toBe(6);

  header = parseFrameHeader(makeHeader({ descriptor: 0x80, window: 0, fcs: 65536 }));
  expect(header.contentSize).toBe(65536);

  header = parseFrameHeader(makeHeader({ descriptor: 0x80, window: 0, fcs: U32_MAX }));
  expect(header.contentSize).toBe(U32_MAX);
});

it('fcs flag 3: 8-byte field, direct value, 0..2^64-1', () => {
  let header = parseFrameHeader(makeHeader({ descriptor: 0xc0, window: 0, fcs: 0 }));
  expect(frameContentSizeFieldSize(header.descriptor)).toBe(8);
  expect(header.contentSize).toBe(0);
  expect(header.headerSize).toBe(10);

  header = parseFrameHeader(makeHeader({ descriptor: 0xc0, window: 0, fcs: 256 }));
  expect(header.contentSize).toBe(256);

  const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
  header = parseFrameHeader(makeHeader({ descriptor: 0xc0, window: 0, fcs: maxSafe }));
  expect(header.contentSize).toBe(Number.MAX_SAFE_INTEGER);

  header = parseFrameHeader(makeHeader({ descriptor: 0xc0, window: 0, fcs: maxSafe + 1n }));
  expect(header.contentSize).toBe(maxSafe + 1n);
  expect(typeof header.contentSize).toBe('bigint');

  const u64Max = (1n << 64n) - 1n;
  header = parseFrameHeader(makeHeader({ descriptor: 0xc0, window: 0, fcs: u64Max }));
  expect(header.contentSize).toBe(u64Max);
});

it('rejects 4-byte FCS field values 0..255 (invalid encoding)', () => {
  for (const bad of [0, 1, 128, 255]) {
    try {
      parseFrameHeader(makeHeader({ descriptor: 0x80, window: 0, fcs: bad }));
      throw new Error(`expected rejection for fcs=${bad}`);
    } catch (error) {
      expect(error).toBeInstanceOf(FrameHeaderError);
      expect((error as FrameHeaderError).code).toBe('invalid-content-size');
    }
  }
});

// ---------------------------------------------------------------------------
// Single_Segment_flag: FCS always present, no window descriptor, window = FCS
// ---------------------------------------------------------------------------

it('single segment fcs flag 0: 1-byte content size 0..255', () => {
  let header = parseFrameHeader(makeHeader({ descriptor: 0x20, fcs: 0 }));
  expect(frameContentSizeFieldSize(header.descriptor)).toBe(1);
  expect(header.contentSize).toBe(0);
  expect(header.windowSize).toBe(0);
  expect(header.windowDescriptor).toBeNull();
  expect(header.headerSize).toBe(2);

  header = parseFrameHeader(makeHeader({ descriptor: 0x20, fcs: 255 }));
  expect(header.contentSize).toBe(255);
  expect(header.windowSize).toBe(255);
});

it('single segment fcs flags 1 and 2: 2-byte field, offset 256', () => {
  let header = parseFrameHeader(makeHeader({ descriptor: 0x60, fcs: 0 }));
  expect(frameContentSizeFieldSize(header.descriptor)).toBe(2);
  expect(header.contentSize).toBe(256);
  expect(header.windowSize).toBe(256);
  expect(header.headerSize).toBe(3);

  header = parseFrameHeader(makeHeader({ descriptor: 0xa0, fcs: 65535 }));
  expect(frameContentSizeFieldSize(header.descriptor)).toBe(2);
  expect(header.contentSize).toBe(65791);
  expect(header.windowSize).toBe(65791);
});

it('single segment fcs flag 3: 4-byte field, direct value', () => {
  let header = parseFrameHeader(makeHeader({ descriptor: 0xe0, fcs: 256 }));
  expect(frameContentSizeFieldSize(header.descriptor)).toBe(4);
  expect(header.contentSize).toBe(256);
  expect(header.windowSize).toBe(256);
  expect(header.headerSize).toBe(5);

  header = parseFrameHeader(makeHeader({ descriptor: 0xe0, fcs: U32_MAX }), {
    maxWindowSize: Infinity,
  });
  expect(header.contentSize).toBe(U32_MAX);
  expect(header.windowSize).toBe(U32_MAX);
});

it('single segment: 4-byte FCS values 0..255 remain invalid', () => {
  expect(() => parseFrameHeader(makeHeader({ descriptor: 0xe0, fcs: 0 }))).toThrow(
    FrameHeaderError,
  );
});

// ---------------------------------------------------------------------------
// Dictionary_ID: every width, and field ordering with single segment
// ---------------------------------------------------------------------------

it('dictionary id flag 0: field absent, id reads as 0', () => {
  const header = parseFrameHeader(makeHeader({ descriptor: 0x40, window: 0, fcs: 0 }));
  expect(header.dictionaryId).toBe(0);
  expect(header.headerSize).toBe(4);
});

it('dictionary id flag 1: 1-byte id 0..255, sits before FCS', () => {
  let header = parseFrameHeader(
    makeHeader({ descriptor: 0x41, window: 0, dictId: 0, fcs: 0 }),
  );
  expect(header.dictionaryId).toBe(0);
  expect(header.contentSize).toBe(256);
  expect(header.headerSize).toBe(5);

  header = parseFrameHeader(
    makeHeader({ descriptor: 0x41, window: 7, dictId: 255, fcs: 10 }),
  );
  expect(header.dictionaryId).toBe(255);
  expect(header.contentSize).toBe(266);
});

it('dictionary id flag 2: 2-byte id 0..65535', () => {
  let header = parseFrameHeader(
    makeHeader({ descriptor: 0x42, window: 0, dictId: 256, fcs: 0 }),
  );
  expect(header.dictionaryId).toBe(256);
  expect(header.headerSize).toBe(6);

  header = parseFrameHeader(
    makeHeader({ descriptor: 0x42, window: 0, dictId: 65535, fcs: 0 }),
  );
  expect(header.dictionaryId).toBe(65535);
});

it('dictionary id flag 3: 4-byte id 0..2^32-1', () => {
  let header = parseFrameHeader(
    makeHeader({ descriptor: 0x43, window: 0, dictId: 65536, fcs: 0 }),
  );
  expect(header.dictionaryId).toBe(65536);
  expect(header.headerSize).toBe(8);

  header = parseFrameHeader(
    makeHeader({ descriptor: 0x43, window: 0, dictId: U32_MAX, fcs: 0 }),
  );
  expect(header.dictionaryId).toBe(U32_MAX);
});

it('regression: single segment + dict id must not be read as window descriptor', () => {
  // descriptor 0x22: single segment (bit 5) + dict id flag 2 (2-byte id),
  // FCS flag 0 -> 1-byte content size. Field order: descriptor, dict id, FCS.
  const data = Uint8Array.from([0x22, 0xd2, 0x04, 0x64]);
  const header = parseFrameHeader(data);
  expect(header.descriptor.singleSegment).toBe(true);
  expect(header.windowDescriptor).toBeNull();
  expect(header.dictionaryId).toBe(0x04d2); // 1234, not misread as window byte
  expect(header.contentSize).toBe(100);
  expect(header.windowSize).toBe(100);
  expect(header.headerSize).toBe(4);
});

// ---------------------------------------------------------------------------
// Checksum flag is preserved; presence states for dict id / content size
// ---------------------------------------------------------------------------

it('checksum flag is preserved in parsed descriptor', () => {
  let header = parseFrameHeader(makeHeader({ descriptor: 0x10, window: 0 }));
  expect(header.descriptor.checksum).toBe(true);
  expect(header.headerSize).toBe(2);

  header = parseFrameHeader(makeHeader({ descriptor: 0x00, window: 0 }));
  expect(header.descriptor.checksum).toBe(false);
});

it('preserves all presence states together (checksum, 4-byte dict, 2-byte FCS)', () => {
  // bits: checksum 0x10 | dict flag 3 (0x03) | fcs flag 1 (0x40) = 0x53
  const header = parseFrameHeader(
    makeHeader({ descriptor: 0x53, window: 0, dictId: 0xdeadbeef, fcs: 74 }),
  );
  expect(header.descriptor.checksum).toBe(true);
  expect(header.dictionaryId).toBe(0xdeadbeef);
  expect(header.contentSize).toBe(330);
  expect(header.headerSize).toBe(2 + 4 + 2);
});

it('single segment + checksum + 4-byte dict + 4-byte FCS: no window byte', () => {
  // 0x20 | 0x10 | 0x03 | 0xc0 = 0xf3
  const header = parseFrameHeader(
    makeHeader({ descriptor: 0xf3, dictId: 1, fcs: 4096 }),
  );
  expect(header.descriptor.singleSegment).toBe(true);
  expect(header.descriptor.checksum).toBe(true);
  expect(header.windowDescriptor).toBeNull();
  expect(header.dictionaryId).toBe(1);
  expect(header.contentSize).toBe(4096);
  expect(header.windowSize).toBe(4096);
  expect(header.headerSize).toBe(1 + 4 + 4);
});

// ---------------------------------------------------------------------------
// Reserved bits
// ---------------------------------------------------------------------------

it('rejects descriptor bytes with reserved bits 3-2 set', () => {
  for (const descriptor of [0x04, 0x08, 0x0c, 0x24, 0xfe]) {
    try {
      parseFrameHeader(Uint8Array.from([descriptor, 0]));
      throw new Error(`expected reserved-bit rejection for 0x${descriptor.toString(16)}`);
    } catch (error) {
      expect(error).toBeInstanceOf(FrameHeaderError);
      expect((error as FrameHeaderError).code).toBe('reserved-bit-set');
    }
  }
});

// ---------------------------------------------------------------------------
// Window descriptor decoding and maximum window enforcement
// ---------------------------------------------------------------------------

it('decodes window descriptor: 1 << exponent * (1024 + 128 * mantissa)', () => {
  expect(decodeWindowSize(windowByte(0, 0))).toBe(1024);
  expect(decodeWindowSize(windowByte(0, 7))).toBe(1920);
  expect(decodeWindowSize(windowByte(1, 0))).toBe(2048);
  expect(decodeWindowSize(windowByte(10, 3))).toBe((1 << 10) * (1024 + 384));

  const header = parseFrameHeader(makeHeader({ descriptor: 0x00, window: windowByte(10, 3) }));
  expect(header.windowSize).toBe((1 << 10) * 1408);
  expect(header.windowDescriptor).toBe(windowByte(10, 3));
});

it('accepts window size exactly at the configured maximum, rejects above', () => {
  // exponent 21, mantissa 0 -> 2^31 exactly (the default max).
  const atLimit = makeHeader({ descriptor: 0x00, window: windowByte(21, 0) });
  let header = parseFrameHeader(atLimit);
  expect(header.windowSize).toBe(2 ** 31);

  // exponent 21, mantissa 1 -> 2^21 * 1152 > 2^31.
  const overLimit = makeHeader({ descriptor: 0x00, window: windowByte(21, 1) });
  try {
    parseFrameHeader(overLimit);
    throw new Error('expected window-too-large');
  } catch (error) {
    expect(error).toBeInstanceOf(FrameHeaderError);
    expect((error as FrameHeaderError).code).toBe('window-too-large');
  }

  // exponent 22 -> 2^32, rejected under default.
  expect(() =>
    parseFrameHeader(makeHeader({ descriptor: 0x00, window: windowByte(22, 0) })),
  ).toThrow(FrameHeaderError);
});

it('default max window size is 2 GiB', () => {
  expect(DEFAULT_MAX_WINDOW_SIZE).toBe(2 ** 31);
});

it('accepts larger windows when configured, up to the RFC maximum (0xff)', () => {
  const rfcMaxWindow = makeHeader({ descriptor: 0x00, window: 0xff });
  // exponent 31, mantissa 7 -> 2^31 * 1920 ~ 3.75 TiB
  const rfcMaxBytes = 2 ** 31 * 1920;
  expect(decodeWindowSize(0xff)).toBe(rfcMaxBytes);

  expect(() => parseFrameHeader(rfcMaxWindow)).toThrow(FrameHeaderError);
  const header = parseFrameHeader(rfcMaxWindow, { maxWindowSize: rfcMaxBytes });
  expect(header.windowSize).toBe(rfcMaxBytes);
});

it('Infinity disables the window size limit', () => {
  const header = parseFrameHeader(makeHeader({ descriptor: 0x00, window: 0xff }), {
    maxWindowSize: Infinity,
  });
  expect(header.windowSize).toBe(2 ** 31 * 1920);
});

it('custom limit also applies to the derived window of single-segment frames', () => {
  const small = makeHeader({ descriptor: 0xe0, fcs: 1024 });
  expect(() => parseFrameHeader(small, { maxWindowSize: 512 })).toThrow(
    FrameHeaderError,
  );
  const header = parseFrameHeader(small, { maxWindowSize: 1024 });
  expect(header.windowSize).toBe(1024);
});

it('accepts bigint limits for windows above 2^53 checks', () => {
  const header = parseFrameHeader(makeHeader({ descriptor: 0x00, window: 0xff }), {
    maxWindowSize: 1n << 64n,
  });
  expect(header.windowSize).toBe(2 ** 31 * 1920);
});

// ---------------------------------------------------------------------------
// Truncation: every field
// ---------------------------------------------------------------------------

function expectTruncated(bytes: Uint8Array, field: string) {
  try {
    parseFrameHeader(bytes);
    throw new Error(`expected truncation error for field ${field}`);
  } catch (error) {
    expect(error).toBeInstanceOf(FrameHeaderError);
    const frameError = error as FrameHeaderError;
    expect(frameError.code).toBe('unexpected-end');
    expect(frameError.field).toBe(field);
  }
}

it('truncated: empty input', () => {
  expectTruncated(new Uint8Array(0), 'descriptor');
});

it('truncated: multi-segment frame missing window descriptor', () => {
  expectTruncated(Uint8Array.from([0x00]), 'windowDescriptor');
});

it('truncated: single-segment missing 1-byte content size', () => {
  expectTruncated(Uint8Array.from([0x20]), 'contentSize');
});

it('truncated: 1-byte dictionary id missing', () => {
  expectTruncated(Uint8Array.from([0x01, 0x00]), 'dictionaryId');
});

it('truncated: 2-byte dictionary id cut short', () => {
  // descriptor 0x02 + window + 1 of 2 dict bytes
  expectTruncated(Uint8Array.from([0x02, 0x00, 0x34]), 'dictionaryId');
});

it('truncated: 4-byte dictionary id cut short by 1..3 bytes', () => {
  const full = [0x03, 0x00, 0x01, 0x02, 0x03, 0x04];
  for (const cut of [3, 4, 5]) {
    expectTruncated(Uint8Array.from(full.slice(0, cut)), 'dictionaryId');
  }
});

it('truncated: 2-byte content size missing entirely and cut short', () => {
  // descriptor 0x40 + window; fcs flag 1 expects 2 bytes
  expectTruncated(Uint8Array.from([0x40, 0x00]), 'contentSize');
  expectTruncated(Uint8Array.from([0x40, 0x00, 0x01]), 'contentSize');
});

it('truncated: 4-byte content size cut short', () => {
  // descriptor 0x80 + window + 2 of 4 fcs bytes
  expectTruncated(Uint8Array.from([0x80, 0x00, 0x00, 0x01]), 'contentSize');
});

it('truncated: 8-byte content size cut short', () => {
  // descriptor 0xc0 + window + 7 of 8 fcs bytes
  expectTruncated(
    Uint8Array.from([0xc0, 0x00, 0, 0, 0, 0, 0, 0, 0]),
    'contentSize',
  );
});

it('truncated: fields after dict id are reached with correct alignment', () => {
  // single segment (0x20) + dict flag 1 (0x01) -> desc, dict, 1-byte fcs.
  expectTruncated(Uint8Array.from([0x21, 0x7b]), 'contentSize');
});

// ---------------------------------------------------------------------------
// End offset must point at the first block header
// ---------------------------------------------------------------------------

const RAW_BLOCK_HEADER = [0x21, 0x43, 0x65];

it('headerEnd points at the first block header (multi-segment, 8-byte fcs, dict)', () => {
  const data = makeHeader({
    descriptor: 0xc3,
    window: 0x00,
    dictId: 0x01020304,
    fcs: 4242,
    trailer: RAW_BLOCK_HEADER,
  });
  const header = parseFrameHeader(data);
  expect(header.headerSize).toBe(1 + 1 + 4 + 8);
  expect(header.headerEnd).toBe(header.headerSize);
  expect(Array.from(data.subarray(header.headerEnd, header.headerEnd + 3))).toEqual(
    RAW_BLOCK_HEADER,
  );

  const block = readBlockHeader(data.subarray(header.headerEnd));
  expect(block).not.toBeNull();
  const value = RAW_BLOCK_HEADER[0]! | (RAW_BLOCK_HEADER[1]! << 8) | (RAW_BLOCK_HEADER[2]! << 16);
  expect(block!.last).toBe(Boolean(value & 1));
  expect(block!.type).toBe((value >> 1) & 3);
  expect(block!.size).toBe(value >> 3);
});

it('headerEnd points at the first block header (single-segment, 1-byte fcs)', () => {
  const data = makeHeader({ descriptor: 0x20, fcs: 5, trailer: RAW_BLOCK_HEADER });
  const header = parseFrameHeader(data);
  expect(header.headerSize).toBe(2);
  expect(Array.from(data.subarray(header.headerEnd))).toEqual(RAW_BLOCK_HEADER);
  expect(readBlockHeader(data.subarray(header.headerEnd))).toEqual({
    last: true,
    type: 0,
    size: (0x21 | (0x43 << 8) | (0x65 << 16)) >> 3,
  });
});

it('supports a leading offset (e.g. after the 4-byte magic number)', () => {
  const headerBytes = makeHeader({ descriptor: 0x40, window: 0, fcs: 0 });
  const withMagic = new Uint8Array(4 + headerBytes.length);
  const magicBytes = leBytes(ZSTD_MAGIC_NUMBER, 4);
  withMagic.set(magicBytes, 0);
  withMagic.set(headerBytes, 4);

  const header = parseFrameHeader(withMagic, { offset: 4 });
  expect(header.headerEnd).toBe(4 + 4);
  expect(header.contentSize).toBe(256);
});

// ---------------------------------------------------------------------------
// Unknown content size + window interaction
// ---------------------------------------------------------------------------

it('unknown content size still requires and decodes a window descriptor', () => {
  const header = parseFrameHeader(makeHeader({ descriptor: 0x00, window: windowByte(8, 2) }));
  expect(header.contentSize).toBeNull();
  expect(header.windowSize).toBe((1 << 8) * (1024 + 256));
  expect(header.headerSize).toBe(2);
});

it('unknown content size can coexist with dict id and checksum', () => {
  // checksum 0x10 | dict flag 2 = 0x12; fcs flag 0 -> unknown
  const header = parseFrameHeader(
    makeHeader({ descriptor: 0x12, window: windowByte(0, 0), dictId: 5000 }),
  );
  expect(header.contentSize).toBeNull();
  expect(header.dictionaryId).toBe(5000);
  expect(header.descriptor.checksum).toBe(true);
  expect(header.windowSize).toBe(1024);
});
