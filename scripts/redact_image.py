#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytesseract",
#   "pillow",
# ]
# ///
"""
redact_image.py — Image OCR and PII blackout helper for pi-redact.

Two modes:
  ocr       Extract text and word bounding boxes from an image (JSON to stdout).
  blackout  Draw black rectangles over specified words in an image.

Usage:
  uv run scripts/redact_image.py ocr --input <image>
  uv run scripts/redact_image.py blackout --input <image> --output <image> --words <word1,word2,...>

Exit codes:
  0  Success
  1  Usage error
  2  Missing dependency (tesseract not installed)
  3  Runtime error
"""

import json
import sys
import os
import argparse
from pathlib import Path


def check_tesseract() -> None:
    """Verify tesseract is installed and accessible."""
    import shutil
    if not shutil.which("tesseract"):
        print(
            json.dumps({
                "error": "tesseract not found",
                "message": (
                    "tesseract-ocr is not installed or not in PATH. "
                    "Install it with: apt install tesseract-ocr  OR  brew install tesseract"
                )
            }),
            file=sys.stderr
        )
        sys.exit(2)


def run_ocr(image_path: str) -> dict:
    """
    Run OCR on the image and return extracted text + per-word bounding boxes.

    Returns:
        {
          "text": "full page text",
          "words": [
            {"text": "Hello", "left": 10, "top": 5, "width": 40, "height": 15, "conf": 95},
            ...
          ]
        }
    """
    import pytesseract
    from PIL import Image

    img = Image.open(image_path)

    # image_to_data returns TSV with level/page/block/par/line/word/left/top/width/height/conf/text
    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)

    words = []
    n_boxes = len(data["level"])
    for i in range(n_boxes):
        # level 5 = word
        if data["level"][i] != 5:
            continue
        text = data["text"][i].strip()
        if not text:
            continue
        conf = int(data["conf"][i])
        if conf < 0:
            continue
        words.append({
            "text": text,
            "left": data["left"][i],
            "top": data["top"][i],
            "width": data["width"][i],
            "height": data["height"][i],
            "conf": conf,
        })

    full_text = pytesseract.image_to_string(img)
    return {"text": full_text.strip(), "words": words}


def normalize(s: str) -> str:
    """Lowercase and strip punctuation for fuzzy matching."""
    return "".join(c for c in s.lower() if c.isalnum())


def words_match(ocr_word: str, pii_token: str) -> bool:
    """
    Return True if the OCR word is part of / matches the PII token.
    Handles:
      - exact match (case-insensitive)
      - OCR word is a substring of the PII token (e.g. email split across chars)
      - PII token is a substring of OCR word
    """
    ocr_n = normalize(ocr_word)
    pii_n = normalize(pii_token)
    if not ocr_n or not pii_n:
        return False
    return ocr_n == pii_n or ocr_n in pii_n or pii_n in ocr_n


def run_blackout(image_path: str, output_path: str, pii_words: list[str]) -> dict:
    """
    Draw black rectangles over OCR words that match any PII token.

    Returns:
        {"redacted_regions": N, "output": "<output_path>"}
    """
    from PIL import Image, ImageDraw

    ocr = run_ocr(image_path)
    img = Image.open(image_path).convert("RGB")
    draw = ImageDraw.Draw(img)

    redacted = 0
    for word_info in ocr["words"]:
        ocr_word = word_info["text"]
        if any(words_match(ocr_word, pii) for pii in pii_words):
            x0 = word_info["left"]
            y0 = word_info["top"]
            x1 = x0 + word_info["width"]
            y1 = y0 + word_info["height"]
            # Add a small padding so the box fully covers the glyph
            pad = 2
            draw.rectangle([x0 - pad, y0 - pad, x1 + pad, y1 + pad], fill="black")
            redacted += 1

    img.save(output_path)
    return {"redacted_regions": redacted, "output": output_path}


def cmd_ocr(args: argparse.Namespace) -> None:
    check_tesseract()
    if not args.input:
        print('{"error": "Missing --input"}', file=sys.stderr)
        sys.exit(1)
    if not Path(args.input).exists():
        print(json.dumps({"error": f"File not found: {args.input}"}), file=sys.stderr)
        sys.exit(3)

    result = run_ocr(args.input)
    print(json.dumps(result))


def cmd_blackout(args: argparse.Namespace) -> None:
    check_tesseract()
    if not args.input:
        print('{"error": "Missing --input"}', file=sys.stderr)
        sys.exit(1)
    if not args.output:
        print('{"error": "Missing --output"}', file=sys.stderr)
        sys.exit(1)
    if not Path(args.input).exists():
        print(json.dumps({"error": f"File not found: {args.input}"}), file=sys.stderr)
        sys.exit(3)

    pii_words: list[str] = []
    if args.words:
        # Accept comma-separated list; also split on semicolons for safety
        raw = args.words.replace(";", ",")
        pii_words = [w.strip() for w in raw.split(",") if w.strip()]

    if not pii_words:
        # Nothing to redact — just copy the image
        import shutil
        shutil.copy2(args.input, args.output)
        print(json.dumps({"redacted_regions": 0, "output": args.output}))
        return

    result = run_blackout(args.input, args.output, pii_words)
    print(json.dumps(result))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Image OCR and PII blackout helper for pi-redact",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- ocr subcommand ---
    ocr_parser = subparsers.add_parser("ocr", help="Extract text + word bounding boxes (JSON to stdout)")
    ocr_parser.add_argument("--input", required=True, help="Path to input image")

    # --- blackout subcommand ---
    bo_parser = subparsers.add_parser("blackout", help="Black out PII words in an image")
    bo_parser.add_argument("--input", required=True, help="Path to input image")
    bo_parser.add_argument("--output", required=True, help="Path to write redacted image")
    bo_parser.add_argument(
        "--words",
        default="",
        help="Comma-separated list of PII words/tokens to black out",
    )

    args = parser.parse_args()

    try:
        if args.command == "ocr":
            cmd_ocr(args)
        elif args.command == "blackout":
            cmd_blackout(args)
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
