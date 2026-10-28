package dev.sovra.worker;

import dev.sovra.quarantine.QuarantineSniff;
import java.io.ByteArrayInputStream;
import java.util.Iterator;
import java.util.Optional;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;

/**
 * Bounded hostile-image scanner (SOV-017). Framework-free and
 * allocation-conscious: header dimensions parse by hand before any
 * decode, pixel and edge caps reject bombs without allocating the
 * bitmap, trailing-data walks reject polyglots, and only then does a
 * decoder attempt confirm the bytes actually render. Every rejection
 * names a machine-readable reason; nothing thrown carries content.
 */
public final class QuarantineScanner {

  /** Largest admittable edge in pixels. */
  public static final int MAX_DIMENSION = 16384;

  /** Largest admittable pixel count (32 megapixels). */
  public static final long MAX_PIXELS = 33_554_432L;

  /** Decoder walk cap: pathological marker/chunk chains stop here. */
  static final int MAX_STRUCTURES = 4096;

  private QuarantineScanner() {}

  public record Verdict(
      boolean clean, String reason, Integer width, Integer height, String detail) {
    public static Verdict clean(int width, int height) {
      return new Verdict(true, "clean", width, height, "");
    }

    public static Verdict rejected(String reason, String detail) {
      return new Verdict(false, reason, null, null, detail);
    }
  }

  public static Verdict scan(byte[] content) {
    if (content == null || content.length == 0) {
      return Verdict.rejected("empty", "no bytes");
    }
    Optional<String> type = QuarantineSniff.actualType(content);
    if (type.isEmpty()) {
      return Verdict.rejected("unknown-type", "magic bytes are not allowlisted");
    }
    try {
      if ("png".equals(type.get())) {
        return scanPng(content);
      }
      return scanJpeg(content);
    } catch (BoundException e) {
      return Verdict.rejected(e.reason(), e.detail());
    } catch (RuntimeException e) {
      return Verdict.rejected("decode-failed", "decoder refused the bytes");
    }
  }

  private static Verdict scanPng(byte[] content) {
    // Walk chunks by hand: length (4BE) + type + data + crc32.
    // IHDR must be first and carry sane dimensions; IEND must be
    // last — trailing bytes are the polyglot channel.
    int at = 8;
    Integer width = null;
    Integer height = null;
    boolean seenIhdr = false;
    boolean seenIend = false;
    for (int chunks = 0; chunks < MAX_STRUCTURES; chunks++) {
      if (at == content.length) {
        break;
      }
      if (at + 8 > content.length) {
        throw new BoundException("truncated", "chunk header cut off");
      }
      long length = u32(content, at);
      if (length > content.length) {
        throw new BoundException("truncated", "chunk overruns the file");
      }
      String type = new String(content, at + 4, 4, java.nio.charset.StandardCharsets.US_ASCII);
      if (!seenIhdr && !"IHDR".equals(type)) {
        throw new BoundException("malformed", "IHDR is not first");
      }
      if ("IHDR".equals(type)) {
        if (seenIhdr || length != 13) {
          throw new BoundException("malformed", "bad IHDR");
        }
        seenIhdr = true;
        width = (int) u32(content, at + 8);
        height = (int) u32(content, at + 12);
        checkDimensions(width, height);
      }
      if ("IEND".equals(type)) {
        seenIend = true;
        at += 12;
        break;
      }
      at += 12 + (int) length;
    }
    if (!seenIhdr || width == null || height == null) {
      throw new BoundException("truncated", "no IHDR");
    }
    if (!seenIend) {
      throw new BoundException("truncated", "no IEND");
    }
    if (at != content.length) {
      throw new BoundException("trailing-data", "bytes follow IEND");
    }
    Decoded decoded = decode(content);
    if (decoded.width() != width || decoded.height() != height) {
      throw new BoundException("dimension-mismatch", "decoder disagrees with IHDR");
    }
    return Verdict.clean(width, height);
  }

  private static Verdict scanJpeg(byte[] content) {
    // Walk markers by hand to the first SOF (dimensions) and then to
    // EOI; trailing bytes after EOI are the polyglot channel. Standalone
    // markers (RSTn, TEM, SOI, EOI) carry no length.
    int at = 2;
    Integer width = null;
    Integer height = null;
    boolean seenSof = false;
    boolean seenEoi = false;
    for (int structures = 0; structures < MAX_STRUCTURES; structures++) {
      if (at + 1 >= content.length) {
        break;
      }
      if ((content[at] & 0xFF) != 0xFF) {
        throw new BoundException("malformed", "expected marker");
      }
      int marker = content[at + 1] & 0xFF;
      if (marker == 0xD9) {
        seenEoi = true;
        at += 2;
        break;
      }
      if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD8)) {
        at += 2;
        continue;
      }
      if (marker == 0x00 || at + 3 >= content.length) {
        throw new BoundException("truncated", "segment header cut off");
      }
      int length = ((content[at + 2] & 0xFF) << 8) | (content[at + 3] & 0xFF);
      if (length < 2 || at + 2 + length > content.length) {
        throw new BoundException("truncated", "segment overruns the file");
      }
      if (!seenSof && marker >= 0xC0 && marker <= 0xCF
          && marker != 0xC4 && marker != 0xC8 && marker != 0xCC) {
        if (length < 7) {
          throw new BoundException("malformed", "short SOF");
        }
        height = ((content[at + 5] & 0xFF) << 8) | (content[at + 6] & 0xFF);
        width = ((content[at + 7] & 0xFF) << 8) | (content[at + 8] & 0xFF);
        checkDimensions(width, height);
        seenSof = true;
      }
      at += 2 + length;
      // Entropy-coded scan data follows SOS: skip bytes until the next
      // 0xFF marker, honoring byte stuffing (FF 00 is data, not a marker).
      if (marker == 0xDA) {
        at = skipScanData(content, at);
      }
    }
    if (!seenSof || width == null || height == null) {
      throw new BoundException("truncated", "no frame header");
    }
    if (!seenEoi) {
      throw new BoundException("truncated", "no EOI");
    }
    if (at != content.length) {
      throw new BoundException("trailing-data", "bytes follow EOI");
    }
    Decoded decoded = decode(content);
    if (decoded.width() != width || decoded.height() != height) {
      throw new BoundException("dimension-mismatch", "decoder disagrees with SOF");
    }
    return Verdict.clean(width, height);
  }

  private static int skipScanData(byte[] content, int at) {
    int cursor = at;
    while (cursor + 1 < content.length) {
      if ((content[cursor] & 0xFF) == 0xFF) {
        int next = content[cursor + 1] & 0xFF;
        if (next == 0x00) {
          cursor += 2;
          continue;
        }
        if (next == 0xFF) {
          cursor += 1;
          continue;
        }
        return cursor;
      }
      cursor++;
    }
    return cursor;
  }

  private static void checkDimensions(int width, int height) {
    if (width <= 0 || height <= 0) {
      throw new BoundException("malformed", "non-positive dimensions");
    }
    if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
      throw new BoundException("dimension-cap", "edge exceeds " + MAX_DIMENSION);
    }
    if ((long) width * (long) height > MAX_PIXELS) {
      throw new BoundException("dimension-cap", "pixel count exceeds cap");
    }
  }

  private record Decoded(int width, int height) {}

  // The reader comes from the bytes, never from a claimed label.
  private static Decoded decode(byte[] content) {
    try (ImageInputStream stream =
        ImageIO.createImageInputStream(new ByteArrayInputStream(content))) {
      Iterator<ImageReader> readers = ImageIO.getImageReaders(stream);
      if (!readers.hasNext()) {
        throw new BoundException("decode-failed", "no decoder for the bytes");
      }
      ImageReader reader = readers.next();
      try {
        reader.setInput(stream, true, true);
        int width = reader.getWidth(0);
        int height = reader.getHeight(0);
        checkDimensions(width, height);
        // Force full decode: header-only reads miss corrupt scan data.
        reader.read(0);
        return new Decoded(width, height);
      } finally {
        reader.dispose();
      }
    } catch (BoundException e) {
      throw e;
    } catch (Exception e) {
      throw new BoundException("decode-failed", "decoder refused the bytes");
    }
  }

  private static long u32(byte[] content, int at) {
    return ((long) (content[at] & 0xFF) << 24)
        | ((content[at + 1] & 0xFF) << 16)
        | ((content[at + 2] & 0xFF) << 8)
        | (content[at + 3] & 0xFF);
  }

  private static final class BoundException extends RuntimeException {
    private final String reason;
    private final String detail;

    BoundException(String reason, String detail) {
      super(reason);
      this.reason = reason;
      this.detail = detail;
    }

    String reason() {
      return reason;
    }

    String detail() {
      return detail;
    }
  }
}
