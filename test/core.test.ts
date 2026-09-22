import {describe, expect, it} from 'vitest';
import {
  ZSTD_MAGIC_NUMBER,
  parseDescriptor,
  parseFrameHeader,
  parseFrameHeaderFields,
  readBlockHeader,
} from '../src/index.js';

const MAGIC = [0x28, 0xb5, 0x2f, 0xfd];
const DICT_LENGTHS = [0, 1, 2, 4];
const CONTENT_LENGTHS = [
  [0, 2, 4, 8],
  [1, 2, 4, 4],
];

const DICT_VALUES = [0n, 0x7fn, 0x7f31n, 0x7f31_2510n];
const CONTENT_VALUES = [
  [null, 0x0302n + 256n, 0x7f31_2510n, 0x1234_5678_9abc_def0n],
  [0n, 0x0302n + 256n, 0x7f31_2510n, 0x7f31_2510n],
];
const CONTENT_RAW_VALUES = [
  [null, 0x0302n, 0x7f31_2510n, 0x1234_5678_9abc_def0n],
  [0n, 0x0302n, 0x7f31_2510n, 0x7f31_2510n],
];
const WINDOW_DESCRIPTOR = 0x0c;
const WINDOW_SIZE = 3072;

function writeLE(
  bytes: number[],
  value: bigint,
  length: number,
): void {
  for (let i = 0; i < length; i++) {
    bytes.push(Number((value >> BigInt(i * 8)) & 0xffn));
  }
}

function descriptor(
  contentSizeFlag: number,
  dictionaryIdFlag: number,
  checksum: boolean,
  singleSegment: boolean,
): number {
  return (
    (contentSizeFlag << 6) |
    dictionaryIdFlag |
    (checksum ? 0x04 : 0) |
    (singleSegment ? 0x20 : 0)
  );
}

function buildFrame(
  contentSizeFlag: number,
  dictionaryIdFlag: number,
  checksum: boolean,
  singleSegment: boolean,
): {bytes: Uint8Array; expectedContentSize: bigint | null} {
  const bytes = [...MAGIC];
  const desc = descriptor(
    contentSizeFlag,
    dictionaryIdFlag,
    checksum,
    singleSegment,
  );
  bytes.push(desc);

  if (!singleSegment) bytes.push(WINDOW_DESCRIPTOR);
  writeLE(bytes, DICT_VALUES[dictionaryIdFlag], DICT_LENGTHS[dictionaryIdFlag]);

  const contentLength =
    CONTENT_LENGTHS[singleSegment ? 1 : 0][contentSizeFlag];
  const expectedContentSize =
    CONTENT_VALUES[singleSegment ? 1 : 0][contentSizeFlag];
  const rawContentSize =
    CONTENT_RAW_VALUES[singleSegment ? 1 : 0][contentSizeFlag];
  if (contentLength > 0) writeLE(bytes, rawContentSize!, contentLength);

  bytes.push(0x03, 0x88, 0x01);
  return {bytes: Uint8Array.from(bytes), expectedContentSize};
}

describe('parseDescriptor', () => {
  it('extracts every descriptor field', () => {
    expect(parseDescriptor(0xe7)).toEqual({
      contentSizeFlag: 3,
      dictionaryIdFlag: 3,
      checksum: true,
      singleSegment: true,
    });
  });

  it('rejects only the reserved descriptor bit in frame header parsing', () => {
    const reserved = new Uint8Array([...MAGIC, 0x08]);
    expect(() => parseFrameHeader(reserved)).toThrow(/reserved bit/);
  });

  it('accepts the currently unused descriptor bit', () => {
    const bytes = new Uint8Array([...MAGIC, 0x10, 0]);
    expect(parseFrameHeader(bytes).descriptor).toBe(0x10);
  });
});

describe('parseFrameHeader field combinations', () => {
  for (let singleSegment = 0; singleSegment < 2; singleSegment++) {
    for (let contentSizeFlag = 0; contentSizeFlag < 4; contentSizeFlag++) {
      for (let dictionaryIdFlag = 0; dictionaryIdFlag < 4; dictionaryIdFlag++) {
        for (let checksum = 0; checksum < 2; checksum++) {
          const name = [
            `singleSegment=${singleSegment}`,
            `contentSizeFlag=${contentSizeFlag}`,
            `dictFlag=${dictionaryIdFlag}`,
            `checksum=${checksum}`,
          ].join(', ');

          it(name, () => {
            const {bytes, expectedContentSize} = buildFrame(
              contentSizeFlag,
              dictionaryIdFlag,
              Boolean(checksum),
              Boolean(singleSegment),
            );
            const parsed = parseFrameHeader(bytes);

            const contentLength =
              CONTENT_LENGTHS[singleSegment][contentSizeFlag];
            const dictLength = DICT_LENGTHS[dictionaryIdFlag];
            const frameHeaderSize =
              1 +
              (singleSegment ? 0 : 1) +
              dictLength +
              contentLength;
            const expectedEndOffset = 4 + frameHeaderSize;
            const expectedWindowSize = singleSegment
              ? expectedContentSize!
              : BigInt(WINDOW_SIZE);

            expect(parsed.magicNumber).toBe(ZSTD_MAGIC_NUMBER);
            expect(parsed.singleSegment).toBe(Boolean(singleSegment));
            expect(parsed.contentSizeFlag).toBe(contentSizeFlag);
            expect(parsed.dictionaryIdFlag).toBe(dictionaryIdFlag);
            expect(parsed.checksum).toBe(Boolean(checksum));
            expect(parsed.hasChecksum).toBe(Boolean(checksum));
            expect(parsed.windowDescriptor).toBe(
              singleSegment ? null : WINDOW_DESCRIPTOR,
            );
            expect(BigInt(parsed.windowSize)).toBe(expectedWindowSize);
            expect(parsed.dictionaryIdFieldSize).toBe(dictLength);
            expect(parsed.dictionaryIdPresent).toBe(dictLength > 0);
            expect(parsed.hasDictionaryId).toBe(dictLength > 0);
            expect(parsed.dictionaryId).toBe(
              dictLength === 0 ? null : Number(DICT_VALUES[dictionaryIdFlag]),
            );
            expect(parsed.contentSizeFieldSize).toBe(contentLength);
            expect(parsed.contentSizePresent).toBe(contentLength > 0);
            expect(parsed.hasContentSize).toBe(contentLength > 0);
            if (contentLength === 0) {
              expect(parsed.contentSize).toBeNull();
            } else {
              expect(BigInt(parsed.contentSize!)).toBe(expectedContentSize);
            }
            expect(parsed.frameHeaderSize).toBe(frameHeaderSize);
            expect(parsed.headerSize).toBe(frameHeaderSize + 4);
            expect(parsed.endOffset).toBe(expectedEndOffset);
            expect(parsed.blockHeaderOffset).toBe(expectedEndOffset);
            expect(readBlockHeader(bytes.subarray(expectedEndOffset))).toEqual({
              last: true,
              type: 1,
              size: 0x3100,
            });
          });
        }
      }
    }
  }
});

describe('field ordering and offsets', () => {
  it('does not read a window descriptor for single segment plus dictionary ID', () => {
    const bytes = new Uint8Array([
      ...MAGIC,
      descriptor(0, 3, false, true),
      0x10, 0x32, 0x54, 0x76,
      0,
    ]);

    const parsed = parseFrameHeader(bytes);
    expect(parsed.windowDescriptor).toBeNull();
    expect(parsed.dictionaryId).toBe(0x76543210);
    expect(parsed.contentSize).toBe(0);
    expect(parsed.windowSize).toBe(0);
    expect(parsed.endOffset).toBe(10);
  });

  it('parses fields from a non-zero offset', () => {
    const body = new Uint8Array([
      ...MAGIC,
      descriptor(1, 1, true, false),
      0,
      0x42,
      ...[0x01, 0x00],
    ]);
    const bytes = new Uint8Array(body.length + 7);
    bytes.set(body, 7);

    const parsed = parseFrameHeader(bytes, {offset: 7});
    expect(parsed.offset).toBe(7);
    expect(parsed.endOffset).toBe(7 + body.length);
    expect(parsed.dictionaryId).toBe(0x42);
    expect(parsed.contentSize).toBe(257);
    expect(parsed.hasChecksum).toBe(true);
  });

  it('exposes the same boundary from parseFrameHeaderFields', () => {
    const {bytes} = buildFrame(0, 0, false, true);
    const parsed = parseFrameHeaderFields(bytes, 4);
    expect(parsed.endOffset).toBe(6);
    expect(parsed.blockHeaderOffset).toBe(6);
  });
});

describe('content size encoding', () => {
  const cases: Array<[number, number, number, bigint]> = [
    [0, 0, 1, 0n],
    [1, 0x0200, 2, 768n],
    [2, 0x1234_5678, 4, 0x1234_5678n],
    [3, 0x76543210, 4, 0x76543210n],
  ];

  it.each(cases)(
    'decodes single-segment content size flag %i',
    (flag, rawValue, length, expected) => {
      const bytes = new Uint8Array([
        ...MAGIC,
        descriptor(flag, 0, false, true),
        ...Array.from({length}, (_, index) =>
          Number((BigInt(rawValue) >> BigInt(index * 8)) & 0xffn),
        ),
      ]);
      const parsed = parseFrameHeader(bytes);
      expect(parsed.contentSizeFieldSize).toBe(length);
      expect(parsed.contentSize).toBe(Number(expected));
      expect(parsed.windowSize).toBe(Number(expected));
    },
  );

  it('decodes unknown, 2-byte, 4-byte, and 64-bit content sizes', () => {
    const values: Array<[number, number, bigint, bigint]> = [
      [1, 2, 0x0100n, 0x0100n + 256n],
      [2, 4, 0x76543210n, 0x76543210n],
      [3, 8, 0x1234_5678_9abc_def0n, 0x1234_5678_9abc_def0n],
    ];

    for (const [flag, length, raw, expected] of values) {
      const bytes = new Uint8Array([
        ...MAGIC,
        descriptor(flag, 0, false, false),
        0,
        ...Array.from({length}, (_, index) =>
          Number((raw >> BigInt(index * 8)) & 0xffn),
        ),
      ]);
      const parsed = parseFrameHeader(bytes, {
        maxWindowSize: Number.MAX_SAFE_INTEGER,
      });
      expect(parsed.contentSize).toBe(
        expected <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(expected)
          : expected,
      );
      expect(parsed.contentSizePresent).toBe(true);
    }

    const unknown = new Uint8Array([
      ...MAGIC,
      descriptor(0, 0, false, false),
      0,
    ]);
    const parsed = parseFrameHeader(unknown);
    expect(parsed.contentSizeFieldSize).toBe(0);
    expect(parsed.contentSize).toBeNull();
    expect(parsed.hasContentSize).toBe(false);
  });
});

describe('truncation', () => {
  const base = buildFrame(3, 3, true, false).bytes;

  it.each([
    ['magic number', 3],
    ['descriptor', 4],
    ['window descriptor', 5],
    ['dictionary ID', 6],
    ['frame content size', 10],
  ])('rejects truncation before %s', (_, length) => {
    const bytes = base.subarray(0, length);
    expect(() => parseFrameHeader(bytes)).toThrow(RangeError);
  });

  it('stops immediately before the first block header', () => {
    const full = buildFrame(3, 3, true, false).bytes;
    const headerOnly = full.subarray(0, full.length - 3);
    const parsed = parseFrameHeader(headerOnly);
    expect(parsed.endOffset).toBe(headerOnly.length);
    expect(readBlockHeader(headerOnly.subarray(parsed.endOffset))).toBeNull();
  });

  it.each([0, 1, 2, 3])(
    'reports the missing byte of dictionary id length flag %i',
    (dictFlag) => {
      const dictLength = DICT_LENGTHS[dictFlag];
      const bytes = new Uint8Array([
        ...MAGIC,
        descriptor(0, dictFlag, false, false),
        0,
        ...new Array(dictLength).fill(0x7f),
      ]);

      if (dictLength === 0) {
        expect(parseFrameHeader(bytes).dictionaryId).toBeNull();
      } else {
        expect(() => parseFrameHeader(bytes.subarray(0, bytes.length - 1))).toThrow(
          /dictionary ID/,
        );
      }
    },
  );

  it.each([0, 1, 2, 3])(
    'reports the missing byte of content size flag %i',
    (contentFlag) => {
      const contentLength = CONTENT_LENGTHS[0][contentFlag];
      const bytes = new Uint8Array([
        ...MAGIC,
        descriptor(contentFlag, 0, false, false),
        0,
        ...new Array(contentLength).fill(0x7f),
      ]);

      if (contentLength === 0) {
        expect(parseFrameHeader(bytes).endOffset).toBe(6);
      } else {
        expect(() =>
          parseFrameHeader(bytes.subarray(0, bytes.length - 1)),
        ).toThrow(/frame content size/);
      }
    },
  );

  it('rejects invalid offsets', () => {
    expect(() => parseFrameHeader(base, {offset: -1})).toThrow(
      /Invalid offset/,
    );
    expect(() => parseFrameHeader(base, {offset: base.length + 1})).toThrow(
      /Invalid offset/,
    );
  });
});

describe('window limits', () => {
  it('accepts a multi-segment window equal to the configured maximum', () => {
    const bytes = new Uint8Array([...MAGIC, 0, 0]);
    const parsed = parseFrameHeader(bytes, {maxWindowSize: 1024});
    expect(parsed.windowSize).toBe(1024);
  });

  it('rejects a multi-segment window above the configured maximum', () => {
    const bytes = new Uint8Array([...MAGIC, 0, 1]);
    expect(() => parseFrameHeader(bytes, {maxWindowSize: 1151})).toThrow(
      /exceeds configured maximum/,
    );
  });

  it('accepts the largest RFC-defined window descriptor at its exact value', () => {
    const exponent = 21;
    const mantissa = 7;
    const maximum =
      (2n ** 31n) + ((2n ** 31n) >> 3n) * 7n;
    const bytes = new Uint8Array([
      ...MAGIC,
      0,
      (exponent << 3) | mantissa,
    ]);

    const parsed = parseFrameHeader(bytes, {maxWindowSize: maximum});
    expect(parsed.windowSize).toBe(Number(maximum));
  });

  it('rejects reserved window descriptor exponents', () => {
    const bytes = new Uint8Array([...MAGIC, 0, 0xb0]);
    expect(() =>
      parseFrameHeader(bytes, {maxWindowSize: Number.MAX_SAFE_INTEGER}),
    ).toThrow(/exponent 22/);
  });

  it('uses content size as the single-segment window and enforces the limit', () => {
    const bytes = new Uint8Array([
      ...MAGIC,
      descriptor(3, 0, false, true),
      0, 0, 0x10, 0,
    ]);

    expect(parseFrameHeader(bytes, {maxWindowSize: 0x100000}).windowSize).toBe(
      0x100000,
    );
    expect(() =>
      parseFrameHeader(bytes, {maxWindowSize: 0xfffff}),
    ).toThrow(/exceeds configured maximum/);
  });
});
