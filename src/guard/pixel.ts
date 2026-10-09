/**
 * Screenshot comparison, with no image-diff dependency: decode both PNGs and
 * count pixels whose channels differ by more than a small tolerance.
 *
 * Same browser, same viewport, same fonts renders the same page to the same
 * pixels, so the tolerance only has to absorb anti-aliasing noise. Anything
 * past the page edge in one image but not the other counts as different, which
 * is what a page that suddenly got much longer or shorter should look like.
 */

import { PNG } from "pngjs";

export interface PixelDiff {
  /** Changed pixels over the larger of the two images, 0 to 1. */
  ratio: number;
  changed: number;
  total: number;
  sizeMismatch: boolean;
  a: { width: number; height: number };
  b: { width: number; height: number };
}

const MAX_PIXELS = 1280 * 4000;

export function decodePng(buf: Buffer): PNG {
  const png = PNG.sync.read(buf);
  if (png.width * png.height > MAX_PIXELS) throw new Error(`screenshot is ${png.width}x${png.height}, over the ${MAX_PIXELS} pixel limit`);
  return png;
}

export function diffPng(aBuf: Buffer, bBuf: Buffer, tolerance = 16): PixelDiff {
  const a = decodePng(aBuf);
  const b = decodePng(bBuf);
  const w = Math.max(a.width, b.width);
  const h = Math.max(a.height, b.height);
  const total = w * h;
  let changed = 0;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const inA = x < a.width && y < a.height;
      const inB = x < b.width && y < b.height;
      if (!inA || !inB) {
        changed++;
        continue;
      }
      const ia = (y * a.width + x) * 4;
      const ib = (y * b.width + x) * 4;
      if (
        Math.abs(a.data[ia] - b.data[ib]) > tolerance ||
        Math.abs(a.data[ia + 1] - b.data[ib + 1]) > tolerance ||
        Math.abs(a.data[ia + 2] - b.data[ib + 2]) > tolerance
      ) {
        changed++;
      }
    }
  }
  return {
    ratio: total ? changed / total : 0,
    changed,
    total,
    sizeMismatch: a.width !== b.width || a.height !== b.height,
    a: { width: a.width, height: a.height },
    b: { width: b.width, height: b.height },
  };
}

/** Test helper and fallback: a solid-colour PNG, optionally with a filled rectangle. */
export function solidPng(width: number, height: number, rgb: [number, number, number], rect?: { x: number; y: number; w: number; h: number; rgb: [number, number, number] }): Buffer {
  const png = new PNG({ width, height });
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const inRect = rect && x >= rect.x && x < rect.x + rect.w && y >= rect.y && y < rect.y + rect.h;
      const c = inRect ? rect!.rgb : rgb;
      const i = (y * width + x) * 4;
      png.data[i] = c[0];
      png.data[i + 1] = c[1];
      png.data[i + 2] = c[2];
      png.data[i + 3] = 255;
    }
  }
  return PNG.sync.write(png);
}
