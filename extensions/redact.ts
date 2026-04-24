/**
 * pi-redact — Redact sensitive information from prompts before they reach the main LLM.
 *
 * Uses a local LLM (Ollama, LM Studio, or any OpenAI-compatible server) to
 * detect PII/sensitive data in user prompts. A fast regex pre-filter catches
 * obvious patterns (emails, SSNs, credit cards, etc.) and the local LLM
 * handles semantic detection (names, addresses, contextual secrets).
 *
 * Configuration is read from Pi's own settings.json under the "redact" key:
 *   Global:  ~/.pi/agent/settings.json
 *   Project: <cwd>/.pi/settings.json
 *
 * Example settings.json entry:
 *   {
 *     "redact": {
 *       "enabled": true,
 *       "host": "http://localhost:11434",
 *       "model": "llama3.2:3b",
 *       "apiFormat": "ollama"
 *     }
 *   }
 */

import type { ExtensionAPI, InputEventResult, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync } from "fs";
import { join, dirname } from "path";
import { homedir, tmpdir } from "os";
import { fileURLToPath } from "url";

// ============================================================================
// Configuration
// ============================================================================

type PiiCategory =
	| "email"
	| "phone"
	| "ssn"
	| "credit_card"
	| "address"
	| "name"
	| "api_key"
	| "password"
	| "ip_address"
	| "date_of_birth";

interface RedactConfig {
	/** Whether redaction is enabled. Default: true */
	enabled: boolean;
	/** Local LLM endpoint URL. Default: "http://localhost:11434" (Ollama default) */
	host: string;
	/** Model to use for redaction. Default: "llama3.2:3b" */
	model: string;
	/** API format: "ollama" | "openai". Default: "ollama" */
	apiFormat: "ollama" | "openai";
	/** Request timeout in ms. Default: 15000 */
	timeoutMs: number;
	/** Categories of PII to detect. Default: all */
	categories: PiiCategory[];
	/** Minimum prompt length to trigger redaction check. Default: 10 */
	minPromptLength: number;
	/** Whether to show a notification when redaction occurs. Default: true */
	notifyOnRedact: boolean;
	/** Whether to scan images for PII. Default: true */
	redactImages: boolean;
	/** Image redaction strategy. Default: "blackout" */
	imageAction: "blackout" | "describe" | "strip";
	/** Vision-capable model for describe mode fallback. Default: "llava" */
	imageModel: string;
}

const ALL_CATEGORIES: PiiCategory[] = [
	"email",
	"phone",
	"ssn",
	"credit_card",
	"address",
	"name",
	"api_key",
	"password",
	"ip_address",
	"date_of_birth",
];

const DEFAULT_CONFIG: RedactConfig = {
	enabled: true,
	host: "http://localhost:11434",
	model: "llama3.2:3b",
	apiFormat: "ollama",
	timeoutMs: 15000,
	categories: ALL_CATEGORIES,
	minPromptLength: 10,
	notifyOnRedact: true,
	redactImages: true,
	imageAction: "blackout",
	imageModel: "llava",
};

/** Pi's config directory name */
const PI_CONFIG_DIR = ".pi";

/**
 * Load redact config from Pi's settings.json files.
 *
 * Reads the "redact" key from:
 *   1. Global: ~/.pi/agent/settings.json
 *   2. Project: <cwd>/.pi/settings.json (overrides global)
 *   3. Environment variables (highest priority)
 */
function loadConfig(cwd: string): RedactConfig {
	const config = { ...DEFAULT_CONFIG };

	// Read from global settings
	const globalSettingsPath = join(homedir(), PI_CONFIG_DIR, "agent", "settings.json");
	mergeFromSettingsFile(config, globalSettingsPath);

	// Read from project settings (overrides global)
	const projectSettingsPath = join(cwd, PI_CONFIG_DIR, "settings.json");
	mergeFromSettingsFile(config, projectSettingsPath);

	// Environment variables (highest priority)
	if (process.env.PI_REDACT_ENABLED !== undefined) {
		config.enabled = process.env.PI_REDACT_ENABLED !== "false" && process.env.PI_REDACT_ENABLED !== "0";
	}
	if (process.env.PI_REDACT_HOST) {
		config.host = process.env.PI_REDACT_HOST;
	}
	if (process.env.PI_REDACT_MODEL) {
		config.model = process.env.PI_REDACT_MODEL;
	}
	if (process.env.PI_REDACT_API_FORMAT) {
		const fmt = process.env.PI_REDACT_API_FORMAT;
		if (fmt === "ollama" || fmt === "openai") {
			config.apiFormat = fmt;
		}
	}
	if (process.env.PI_REDACT_TIMEOUT_MS) {
		const parsed = Number.parseInt(process.env.PI_REDACT_TIMEOUT_MS, 10);
		if (!Number.isNaN(parsed) && parsed > 0) {
			config.timeoutMs = parsed;
		}
	}

	return config;
}

function mergeFromSettingsFile(config: RedactConfig, filePath: string): void {
	if (!existsSync(filePath)) {
		return;
	}
	try {
		const content = readFileSync(filePath, "utf-8");
		const settings = JSON.parse(content) as Record<string, unknown>;
		const redactSettings = settings.redact;
		if (!redactSettings || typeof redactSettings !== "object") {
			return;
		}
		const rs = redactSettings as Record<string, unknown>;
		if (typeof rs.enabled === "boolean") config.enabled = rs.enabled;
		if (typeof rs.host === "string") config.host = rs.host;
		if (typeof rs.model === "string") config.model = rs.model;
		if (rs.apiFormat === "ollama" || rs.apiFormat === "openai") config.apiFormat = rs.apiFormat;
		if (typeof rs.timeoutMs === "number" && rs.timeoutMs > 0) config.timeoutMs = rs.timeoutMs;
		if (typeof rs.minPromptLength === "number" && rs.minPromptLength >= 0) config.minPromptLength = rs.minPromptLength;
		if (typeof rs.notifyOnRedact === "boolean") config.notifyOnRedact = rs.notifyOnRedact;
		if (typeof rs.redactImages === "boolean") config.redactImages = rs.redactImages;
		if (rs.imageAction === "blackout" || rs.imageAction === "describe" || rs.imageAction === "strip") config.imageAction = rs.imageAction;
		if (typeof rs.imageModel === "string") config.imageModel = rs.imageModel;
		if (Array.isArray(rs.categories)) {
			const valid = rs.categories.filter((c): c is PiiCategory => ALL_CATEGORIES.includes(c as PiiCategory));
			if (valid.length > 0) config.categories = valid;
		}
	} catch {
		// Silently ignore parse errors — Pi's own SettingsManager does the same
	}
}

// ============================================================================
// Regex-based PII Detection (Fast Path)
// ============================================================================

interface PiiMatch {
	original: string;
	type: PiiCategory;
	placeholder: string;
	start: number;
	end: number;
}

const PII_PATTERNS: Partial<Record<PiiCategory, RegExp>> = {
	email: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
	phone: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
	ssn: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
	credit_card: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
	api_key: /\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[A-Za-z0-9]{20,}\b/gi,
	ip_address: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
};

function detectWithRegex(text: string, categories: PiiCategory[]): PiiMatch[] {
	const matches: PiiMatch[] = [];
	let counter = 0;

	for (const category of categories) {
		const pattern = PII_PATTERNS[category];
		if (!pattern) continue;

		// Reset lastIndex for global regex
		pattern.lastIndex = 0;
		let match: RegExpExecArray | null = null;
		while ((match = pattern.exec(text)) !== null) {
			counter++;
			matches.push({
				original: match[0],
				type: category,
				placeholder: `[REDACTED_${category.toUpperCase()}_${counter}]`,
				start: match.index,
				end: match.index + match[0].length,
			});
		}
	}

	return matches;
}

// ============================================================================
// LLM-based PII Detection
// ============================================================================

const DETECTION_PROMPT = `You are a PII (Personally Identifiable Information) detector. Analyze the following text and identify any sensitive information that should be redacted before sending to an external AI service.

For each piece of sensitive data found, output a JSON object on its own line with:
- "original": the exact text to redact (must match exactly as it appears)
- "type": the category (email, phone, ssn, credit_card, address, name, api_key, password, ip_address, date_of_birth)

If no sensitive information is found, output exactly: {"found": false}

IMPORTANT:
- Only flag actual PII, not general technical terms or code
- Do NOT flag placeholder examples like "user@example.com"
- Be precise: "original" must be an exact substring of the input
- Output ONLY valid JSON lines, no explanation

Text to analyze:
---
`;

interface LlmFinding {
	original: string;
	type: string;
}

async function queryOllama(host: string, model: string, prompt: string, timeoutMs: number): Promise<string> {
	const url = `${host.replace(/\/+$/, "")}/api/generate`;
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), timeoutMs);

	try {
		const response = await fetch(url, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				model,
				prompt,
				stream: false,
				options: {
					temperature: 0,
					num_predict: 1024,
				},
			}),
			signal: controller.signal,
		});

		if (!response.ok) {
			throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
		}

		const data = (await response.json()) as { response?: string };
		return data.response ?? "";
	} finally {
		clearTimeout(timeout);
	}
}

async function queryOpenAI(host: string, model: string, prompt: string, timeoutMs: number): Promise<string> {
	const url = `${host.replace(/\/+$/, "")}/v1/chat/completions`;
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), timeoutMs);

	try {
		const response = await fetch(url, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				model,
				messages: [
					{ role: "user", content: prompt },
				],
				temperature: 0,
				max_tokens: 1024,
			}),
			signal: controller.signal,
		});

		if (!response.ok) {
			throw new Error(`OpenAI-compatible API error: ${response.status} ${response.statusText}`);
		}

		const data = (await response.json()) as { choices?: Array<{ message?: { content?: string } }> };
		return data.choices?.[0]?.message?.content ?? "";
	} finally {
		clearTimeout(timeout);
	}
}

function parseLlmResponse(response: string, categories: PiiCategory[]): LlmFinding[] {
	const findings: LlmFinding[] = [];
	const lines = response.trim().split("\n");

	for (const line of lines) {
		const trimmed = line.trim();
		if (!trimmed) continue;

		try {
			const parsed = JSON.parse(trimmed) as Record<string, unknown>;

			// Check for "no findings" response
			if (parsed.found === false) continue;

			if (typeof parsed.original === "string" && typeof parsed.type === "string") {
				// Only accept findings in our configured categories
				if (categories.includes(parsed.type as PiiCategory)) {
					findings.push({
						original: parsed.original,
						type: parsed.type,
					});
				}
			}
		} catch {
			// Try to extract JSON from a line that has extra text around it
			const jsonMatch = trimmed.match(/\{[^}]+\}/);
			if (jsonMatch) {
				try {
					const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;
					if (typeof parsed.original === "string" && typeof parsed.type === "string") {
						if (categories.includes(parsed.type as PiiCategory)) {
							findings.push({
								original: parsed.original,
								type: parsed.type,
							});
						}
					}
				} catch {
					// Skip unparseable lines
				}
			}
		}
	}

	return findings;
}

async function detectWithLLM(text: string, config: RedactConfig): Promise<LlmFinding[]> {
	const prompt = `${DETECTION_PROMPT}${text}\n---`;

	try {
		const response =
			config.apiFormat === "ollama"
				? await queryOllama(config.host, config.model, prompt, config.timeoutMs)
				: await queryOpenAI(config.host, config.model, prompt, config.timeoutMs);

		return parseLlmResponse(response, config.categories);
	} catch {
		// LLM unavailable — fall back to regex-only (handled by caller)
		return [];
	}
}

// ============================================================================
// Redaction Pipeline
// ============================================================================

interface RedactResult {
	text: string;
	redacted: boolean;
	findings: PiiMatch[];
}

function mergeFindings(regexMatches: PiiMatch[], llmFindings: LlmFinding[], text: string): PiiMatch[] {
	const allMatches = [...regexMatches];
	let counter = regexMatches.length;

	// Add LLM findings that weren't already caught by regex
	for (const finding of llmFindings) {
		const alreadyCaught = regexMatches.some(
			(m) => m.original === finding.original || m.original.includes(finding.original) || finding.original.includes(m.original),
		);
		if (alreadyCaught) continue;

		// Verify the finding actually exists in the text
		const idx = text.indexOf(finding.original);
		if (idx === -1) continue;

		counter++;
		allMatches.push({
			original: finding.original,
			type: finding.type as PiiCategory,
			placeholder: `[REDACTED_${finding.type.toUpperCase()}_${counter}]`,
			start: idx,
			end: idx + finding.original.length,
		});
	}

	// Sort by start position, longest match first for ties
	allMatches.sort((a, b) => a.start - b.start || b.original.length - a.original.length);

	// Remove overlapping matches (keep the first/longest)
	const deduped: PiiMatch[] = [];
	let lastEnd = -1;
	for (const match of allMatches) {
		if (match.start >= lastEnd) {
			deduped.push(match);
			lastEnd = match.end;
		}
	}

	return deduped;
}

function applyRedactions(text: string, findings: PiiMatch[]): string {
	if (findings.length === 0) return text;

	// Apply from end to start to preserve indices
	let result = text;
	const sorted = [...findings].sort((a, b) => b.start - a.start);

	for (const finding of sorted) {
		result = result.slice(0, finding.start) + finding.placeholder + result.slice(finding.end);
	}

	return result;
}

async function redactPrompt(text: string, config: RedactConfig): Promise<RedactResult> {
	if (text.length < config.minPromptLength) {
		return { text, redacted: false, findings: [] };
	}

	// 1. Run regex-based pre-filter (fast, always available)
	const regexFindings = detectWithRegex(text, config.categories);

	// 2. Query local LLM for semantic detection
	const llmFindings = await detectWithLLM(text, config);

	// 3. Merge and deduplicate
	const allFindings = mergeFindings(regexFindings, llmFindings, text);

	if (allFindings.length === 0) {
		return { text, redacted: false, findings: [] };
	}

	// 4. Apply redactions
	const redactedText = applyRedactions(text, allFindings);

	return { text: redactedText, redacted: true, findings: allFindings };
}

// ============================================================================
// Whimsical Progress Messages
// ============================================================================

const REDACT_MESSAGES = [
	"🛡️ Scanning for secrets...",
	"🔍 Hunting for PII...",
	"🕵️ Inspecting your prose...",
	"🧹 Sweeping for sensitive bits...",
	"🔐 Checking for classified info...",
	"🛡️ Deploying privacy shields...",
	"🔎 Magnifying the details...",
	"🧪 Analyzing for leaks...",
	"🔒 Engaging redaction protocols...",
	"🫣 Averting eyes from secrets...",
	"🧙 Casting obfuscation spell...",
	"🎭 Masking the sensitive bits...",
	"🤫 Shh... finding secrets...",
	"📸 Inspecting images for PII...",
	"🖼️ Analyzing visual content...",
	"🔲 Preparing redaction boxes...",
];

// ============================================================================
// Image Redaction Pipeline
// ============================================================================

/** Regex to detect image file paths in prompt text */
const IMAGE_PATH_PATTERN = /(?:^|\s)((?:\/[\w.\-~]+)+\.(?:png|jpe?g|gif|webp|bmp|tiff?))\b/gi;

interface ImageRedactResult {
	text: string;
	images: Array<{ type: string; source: { type: string; mediaType: string; data: string } }>;
	imageFindings: Array<{ type: string; source: string }>;
}

interface OcrWord {
	text: string;
	left: number;
	top: number;
	width: number;
	height: number;
	conf: number;
}

interface OcrResult {
	text: string;
	words: OcrWord[];
}

function getScriptDir(): string {
	try {
		return dirname(fileURLToPath(import.meta.url));
	} catch {
		return __dirname;
	}
}

function getRedactImageScriptPath(): string {
	const extDir = getScriptDir();
	// scripts/ is a sibling of extensions/
	return join(dirname(extDir), "scripts", "redact_image.py");
}

function extractImagePaths(text: string): Array<{ path: string; start: number; end: number }> {
	const results: Array<{ path: string; start: number; end: number }> = [];
	IMAGE_PATH_PATTERN.lastIndex = 0;
	let m: RegExpExecArray | null = null;
	while ((m = IMAGE_PATH_PATTERN.exec(text)) !== null) {
		const path = m[1];
		const start = m.index + m[0].indexOf(path);
		results.push({ path, start, end: start + path.length });
	}
	return results;
}

function mimeFromExt(ext: string): string {
	const map: Record<string, string> = {
		".png": "image/png",
		".jpg": "image/jpeg",
		".jpeg": "image/jpeg",
		".gif": "image/gif",
		".webp": "image/webp",
		".bmp": "image/bmp",
		".tiff": "image/tiff",
		".tif": "image/tiff",
	};
	return map[ext.toLowerCase()] ?? "image/png";
}

function saveBase64ToTemp(data: string, mimeType: string): string {
	const dir = join(tmpdir(), "pi-redact-images");
	mkdirSync(dir, { recursive: true });
	const ext = mimeType.includes("png") ? ".png" : mimeType.includes("jpeg") ? ".jpg" : ".png";
	const name = `img-${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`;
	const filePath = join(dir, name);
	writeFileSync(filePath, Buffer.from(data, "base64"));
	return filePath;
}

async function runBlackoutScript(
	mode: "ocr" | "blackout",
	args: string[],
	pi: ExtensionAPI,
): Promise<{ stdout: string; ok: boolean }> {
	const scriptPath = getRedactImageScriptPath();
	if (!existsSync(scriptPath)) {
		return { stdout: "", ok: false };
	}
	try {
		const result = await pi.exec("uv", ["run", scriptPath, mode, ...args], { timeout: 30000 });
		return { stdout: result.stdout ?? "", ok: result.code === 0 };
	} catch {
		return { stdout: "", ok: false };
	}
}

async function ocrImage(imagePath: string, pi: ExtensionAPI): Promise<OcrResult | null> {
	const { stdout, ok } = await runBlackoutScript("ocr", ["--input", imagePath], pi);
	if (!ok) return null;
	try {
		return JSON.parse(stdout) as OcrResult;
	} catch {
		return null;
	}
}

async function blackoutImage(
	imagePath: string,
	outputPath: string,
	piiWords: string[],
	pi: ExtensionAPI,
): Promise<boolean> {
	const { ok } = await runBlackoutScript(
		"blackout",
		["--input", imagePath, "--output", outputPath, "--words", piiWords.join(",")],
		pi,
	);
	return ok;
}

async function extractImageTextViaMarkitdown(imagePath: string, pi: ExtensionAPI): Promise<string | null> {
	try {
		const result = await pi.exec("uvx", ["markitdown", imagePath], { timeout: 30000 });
		if (result.code === 0 && result.stdout) return result.stdout.trim();
		return null;
	} catch {
		return null;
	}
}

async function extractImageTextViaVisionLLM(imagePath: string, config: RedactConfig): Promise<string | null> {
	const imageData = readFileSync(imagePath).toString("base64");
	const ext = imagePath.slice(imagePath.lastIndexOf("."));
	const mime = mimeFromExt(ext);

	try {
		const url = `${config.host.replace(/\/+$/, "")}/api/generate`;
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), config.timeoutMs);
		try {
			const resp = await fetch(url, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					model: config.imageModel,
					prompt: "Describe this image in detail. Include all visible text. Do not omit any text content.",
					images: [imageData],
					stream: false,
				}),
				signal: controller.signal,
			});
			if (!resp.ok) return null;
			const data = (await resp.json()) as { response?: string };
			return data.response ?? null;
		} finally {
			clearTimeout(timeout);
		}
	} catch {
		return null;
	}
}

/**
 * Redact a single image file. Returns the redacted image path (blackout),
 * a text description (describe), or null (strip / failure).
 */
async function redactSingleImage(
	imagePath: string,
	config: RedactConfig,
	pi: ExtensionAPI,
): Promise<{ action: "replaced" | "described" | "stripped"; outputPath?: string; description?: string; piiTypes: string[] }> {
	const piiTypes: string[] = [];

	// --- blackout mode ---
	if (config.imageAction === "blackout") {
		const ocrResult = await ocrImage(imagePath, pi);
		if (ocrResult && ocrResult.text.length > 0) {
			const textResult = await redactPrompt(ocrResult.text, config);
			if (textResult.redacted && textResult.findings.length > 0) {
				for (const f of textResult.findings) piiTypes.push(f.type);
				const piiWords = textResult.findings.map((f) => f.original);
				const outPath = imagePath.replace(/(\.\w+)$/, `-redacted$1`);
				const ok = await blackoutImage(imagePath, outPath, piiWords, pi);
				if (ok) return { action: "replaced", outputPath: outPath, piiTypes };
			} else {
				// OCR found text but no PII — image is clean
				return { action: "replaced", outputPath: imagePath, piiTypes: [] };
			}
		}
		// Fallback: blackout failed (no tesseract/uv) → try describe
	}

	// --- describe mode (or blackout fallback) ---
	if (config.imageAction === "describe" || config.imageAction === "blackout") {
		let extractedText = await extractImageTextViaMarkitdown(imagePath, pi);
		if (!extractedText) {
			extractedText = await extractImageTextViaVisionLLM(imagePath, config);
		}
		if (extractedText) {
			const textResult = await redactPrompt(extractedText, config);
			if (textResult.redacted) {
				for (const f of textResult.findings) piiTypes.push(f.type);
				return { action: "described", description: textResult.text, piiTypes };
			}
			// Text extracted but no PII
			return { action: "described", description: extractedText, piiTypes: [] };
		}
		// Fallback → strip
	}

	// --- strip mode (or final fallback) ---
	return { action: "stripped", piiTypes };
}

async function redactImages(
	text: string,
	images: Array<{ type: string; source: { type: string; mediaType: string; data: string } }> | undefined,
	config: RedactConfig,
	pi: ExtensionAPI,
): Promise<ImageRedactResult> {
	const allFindings: Array<{ type: string; source: string }> = [];
	let processedText = text;
	const processedImages = [...(images ?? [])];

	// 1. Process image file paths in text
	const imagePaths = extractImagePaths(text);
	// Process from end to preserve indices
	for (const imgRef of [...imagePaths].reverse()) {
		if (!existsSync(imgRef.path)) continue;
		const result = await redactSingleImage(imgRef.path, config, pi);
		if (result.piiTypes.length === 0 && result.action === "replaced") continue; // clean image
		for (const t of result.piiTypes) allFindings.push({ type: t, source: imgRef.path });

		if (result.action === "replaced" && result.outputPath && result.outputPath !== imgRef.path) {
			processedText = processedText.slice(0, imgRef.start) + result.outputPath + processedText.slice(imgRef.end);
		} else if (result.action === "described" && result.description) {
			const replacement = `[Image description: ${result.description}]`;
			processedText = processedText.slice(0, imgRef.start) + replacement + processedText.slice(imgRef.end);
		} else if (result.action === "stripped") {
			processedText = processedText.slice(0, imgRef.start) + "[REDACTED_IMAGE]" + processedText.slice(imgRef.end);
		}
	}

	// 2. Process base64 images in event.images
	const keptImages: typeof processedImages = [];
	for (const img of processedImages) {
		if (img.type !== "image" || img.source?.type !== "base64") {
			keptImages.push(img);
			continue;
		}
		const tmpPath = saveBase64ToTemp(img.source.data, img.source.mediaType);
		try {
			const result = await redactSingleImage(tmpPath, config, pi);
			if (result.piiTypes.length === 0 && result.action !== "stripped") {
				keptImages.push(img); // clean — keep original
				continue;
			}
			for (const t of result.piiTypes) allFindings.push({ type: t, source: "clipboard" });

			if (result.action === "replaced" && result.outputPath) {
				const newData = readFileSync(result.outputPath).toString("base64");
				keptImages.push({ type: "image", source: { type: "base64", mediaType: img.source.mediaType, data: newData } });
				try { unlinkSync(result.outputPath); } catch { /* ignore */ }
			} else if (result.action === "described" && result.description) {
				// Image replaced by text — append to prompt text instead
				processedText += `\n\n[Image description: ${result.description}]`;
			}
			// stripped → image just gets dropped
		} finally {
			try { unlinkSync(tmpPath); } catch { /* ignore */ }
		}
	}

	return { text: processedText, images: keptImages, imageFindings: allFindings };
}

// ============================================================================
// Extension
// ============================================================================

export default function redactExtension(pi: ExtensionAPI): void {
	let config: RedactConfig = DEFAULT_CONFIG;
	let lastRedactionInfo: RedactResult | null = null;
	let llmAvailable: boolean | null = null; // null = unknown

	// --- Load config on session start ---
	pi.on("session_start", async (_event, ctx) => {
		config = loadConfig(ctx.cwd);
		llmAvailable = null; // Reset availability check for new session

		if (config.enabled && ctx.hasUI) {
			ctx.ui.setStatus("redact", "🛡️");
		}
	});

	// --- Register CLI flag ---
	pi.registerFlag("redact", {
		description: "Enable/disable PII redaction (overrides settings.json)",
		type: "boolean",
		default: true,
	});

	// --- Register /redact command ---
	pi.registerCommand("redact", {
		description: "Show redaction status, or toggle: /redact on|off|status|model <name>|host <url>",
		async handler(args, ctx) {
			const trimmed = args.trim();

			if (trimmed === "status" || trimmed === "") {
				const statusLines = [
					`pi-redact status:`,
					`  enabled:      ${config.enabled}`,
					`  host:         ${config.host}`,
					`  model:        ${config.model}`,
					`  apiFormat:    ${config.apiFormat}`,
					`  timeoutMs:    ${config.timeoutMs}`,
					`  categories:   ${config.categories.join(", ")}`,
					`  redactImages: ${config.redactImages}`,
					`  imageAction:  ${config.imageAction}`,
					`  imageModel:   ${config.imageModel}`,
					`  llm:          ${llmAvailable === null ? "not checked yet" : llmAvailable ? "reachable" : "unreachable (regex-only mode)"}`,
				];
				if (lastRedactionInfo?.redacted) {
					statusLines.push(
						`  last redaction: ${lastRedactionInfo.findings.length} item(s) — ${[...new Set(lastRedactionInfo.findings.map((f) => f.type))].join(", ")}`,
					);
				}
				ctx.ui.notify(statusLines.join("\n"), "info");
				return;
			}

			if (trimmed === "on") {
				config.enabled = true;
				ctx.ui.setStatus("redact", "🛡️");
				ctx.ui.notify("pi-redact enabled", "info");
				return;
			}

			if (trimmed === "off") {
				config.enabled = false;
				ctx.ui.setStatus("redact", undefined);
				ctx.ui.notify("pi-redact disabled", "warning");
				return;
			}

			if (trimmed.startsWith("model ")) {
				config.model = trimmed.slice(6).trim();
				llmAvailable = null; // Re-check on next prompt
				ctx.ui.notify(`pi-redact model set to: ${config.model}`, "info");
				return;
			}

			if (trimmed.startsWith("host ")) {
				config.host = trimmed.slice(5).trim();
				llmAvailable = null;
				ctx.ui.notify(`pi-redact host set to: ${config.host}`, "info");
				return;
			}

			ctx.ui.notify(
				"Usage: /redact [status|on|off|model <name>|host <url>]",
				"info",
			);
		},
	});

	// --- Core: intercept user input and redact ---
	pi.on("input", async (event, ctx): Promise<InputEventResult | void> => {
		// Check CLI flag override
		const flagValue = pi.getFlag("redact");
		if (flagValue === false) {
			return { action: "continue" };
		}

		if (!config.enabled) {
			return { action: "continue" };
		}

		// Don't redact extension-generated messages (avoid infinite loops)
		if (event.source === "extension") {
			return { action: "continue" };
		}

		// Don't redact slash commands
		if (event.text.startsWith("/")) {
			return { action: "continue" };
		}

		const hasImages = config.redactImages && ((event.images && event.images.length > 0) || IMAGE_PATH_PATTERN.test(event.text));
		// Reset regex lastIndex after test
		IMAGE_PATH_PATTERN.lastIndex = 0;

		const hasText = event.text.length >= config.minPromptLength;

		if (!hasText && !hasImages) {
			return { action: "continue" };
		}

		// Start whimsical progress rotation
		let msgIdx = Math.floor(Math.random() * REDACT_MESSAGES.length);
		if (ctx.hasUI) {
			ctx.ui.setWorkingMessage(REDACT_MESSAGES[msgIdx]);
			ctx.ui.setStatus("redact", "🛡️ scanning…");
		}
		const ticker = setInterval(() => {
			msgIdx = (msgIdx + 1) % REDACT_MESSAGES.length;
			if (ctx.hasUI) ctx.ui.setWorkingMessage(REDACT_MESSAGES[msgIdx]);
		}, 1500);

		try {
			let processedText = event.text;
			let processedImages = event.images ?? [];
			let totalFindings = 0;
			const allTypes: string[] = [];

			// 1. Redact images (if enabled and present)
			if (hasImages) {
				const imageResult = await redactImages(processedText, event.images, config, pi);
				processedText = imageResult.text;
				processedImages = imageResult.images as typeof processedImages;
				for (const f of imageResult.imageFindings) {
					totalFindings++;
					if (!allTypes.includes(f.type)) allTypes.push(f.type);
				}
			}

			// 2. Redact text PII
			if (hasText) {
				const textResult = await redactPrompt(processedText, config);
				llmAvailable = true;

				if (textResult.redacted) {
					processedText = textResult.text;
					totalFindings += textResult.findings.length;
					for (const f of textResult.findings) {
						if (!allTypes.includes(f.type)) allTypes.push(f.type);
					}
					lastRedactionInfo = textResult;
				}
			}

			// 3. Nothing redacted
			if (totalFindings === 0) {
				return { action: "continue" };
			}

			// 4. Notify user
			if (config.notifyOnRedact && ctx.hasUI) {
				ctx.ui.notify(
					`🛡️ Redacted ${totalFindings} sensitive item(s): ${allTypes.join(", ")}`,
					"warning",
				);
				ctx.ui.setStatus("redact", `🛡️ ${totalFindings} redacted`);
			}

			return {
				action: "transform",
				text: processedText,
				images: processedImages,
			};
		} catch (error) {
			if (ctx.hasUI) {
				const msg = error instanceof Error ? error.message : String(error);
				ctx.ui.notify(`⚠️ pi-redact error (prompt sent unredacted): ${msg}`, "warning");
			}
			return { action: "continue" };
		} finally {
			clearInterval(ticker);
			if (ctx.hasUI) {
				ctx.ui.setWorkingMessage();
				// Restore idle status after a short delay
				setTimeout(() => {
					if (config.enabled && ctx.hasUI) ctx.ui.setStatus("redact", "🛡️");
				}, 5000);
			}
		}
	});

	// --- Inject context message when redaction occurred ---
	pi.on("before_agent_start", async () => {
		if (!lastRedactionInfo?.redacted) {
			return;
		}

		const info = lastRedactionInfo;
		lastRedactionInfo = null;

		const types = [...new Set(info.findings.map((f) => f.type))];

		return {
			message: {
				customType: "redact-notice",
				content: `[pi-redact] ${info.findings.length} piece(s) of sensitive information (${types.join(", ")}) were redacted from the user's prompt. Placeholders like [REDACTED_EMAIL_1] replace the original values. Do not ask the user to provide the redacted information.`,
				display: false,
				details: {
					count: info.findings.length,
					types,
				},
			},
		};
	});
}
