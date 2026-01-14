import DOMPurify from "isomorphic-dompurify";
import type { DOMPurifyConfig, FieldConfig, SanitizationContext, SanitizationMode } from "../types";

/**
 * Check if a value is a plain object
 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.prototype.toString.call(value) === "[object Object]"
  );
}

/**
 * Check if a field should be sanitized based on whitelist/blacklist
 */
export function shouldSanitizeField(
  fieldPath: string,
  options: SanitizationContext["options"],
): boolean {
  // If whitelist is defined, only sanitize whitelisted fields
  if (options.whitelist && options.whitelist.length > 0) {
    return options.whitelist.some(
      (pattern) => fieldPath === pattern || fieldPath.startsWith(`${pattern}.`),
    );
  }

  // If blacklist is defined, skip blacklisted fields
  if (options.blacklist && options.blacklist.length > 0) {
    return !options.blacklist.some(
      (pattern) => fieldPath === pattern || fieldPath.startsWith(`${pattern}.`),
    );
  }

  return true;
}

/**
 * Get field configuration
 */
export function getFieldConfig(
  fieldPath: string,
  options: SanitizationContext["options"],
): FieldConfig | null {
  if (!options.fields) return null;

  // Exact match
  if (options.fields[fieldPath]) {
    return options.fields[fieldPath];
  }

  // Check parent paths (e.g., 'user.profile' matches 'user')
  const parts = fieldPath.split(".");
  for (let i = parts.length - 1; i > 0; i--) {
    const parentPath = parts.slice(0, i).join(".");
    if (options.fields[parentPath]) {
      return options.fields[parentPath];
    }
  }

  return null;
}

/**
 * Sanitize a string value based on mode
 */
export function sanitizeString(
  value: string,
  mode: SanitizationMode,
  config?: DOMPurifyConfig,
): string {
  if (mode === "strict") {
    // Strip all HTML
    return DOMPurify.sanitize(value, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
  }

  if (mode === "html") {
    // Allow safe HTML with custom config
    return DOMPurify.sanitize(value, config || {});
  }

  // mode === 'skip' or 'custom' (custom is handled elsewhere)
  return value;
}

/**
 * Check if field should be skipped based on config
 */
export function shouldSkipField(
  fieldPath: string,
  fieldConfig: FieldConfig | null,
  ctx: SanitizationContext,
): boolean {
  if (!shouldSanitizeField(fieldPath, ctx.options)) {
    ctx.options.onSkip?.(fieldPath, ctx.path);
    return true;
  }

  if (fieldConfig?.mode === "skip") {
    ctx.options.onSkip?.(fieldPath, ctx.path);
    return true;
  }

  return false;
}

/**
 * Apply custom sanitizer to value
 */
export function applyCustomSanitizer(
  value: unknown,
  fieldPath: string,
  sanitizer: (value: unknown) => unknown,
  ctx: SanitizationContext,
): unknown {
  const sanitized = sanitizer(value);
  ctx.options.onSanitize?.(fieldPath, value, sanitized);
  return sanitized;
}

/**
 * Sanitize a string value
 */
export function sanitizeStringValue(
  value: string,
  fieldPath: string,
  mode: SanitizationMode,
  config: DOMPurifyConfig | undefined,
  ctx: SanitizationContext,
): string {
  const sanitized = sanitizeString(value, mode, config);
  if (sanitized !== value) {
    ctx.options.onSanitize?.(fieldPath, value, sanitized);
  }
  return sanitized;
}

/**
 * Sanitize an array value
 */
export function sanitizeArrayValue(
  value: unknown[],
  fieldPath: string,
  mode: SanitizationMode,
  config: DOMPurifyConfig | undefined,
  ctx: SanitizationContext,
): unknown {
  if (ctx.options.arrays === "skip") {
    ctx.options.onSkip?.(fieldPath, value);
    return value;
  }

  if (ctx.options.arrays === "join") {
    const joined = value.join(" ");
    const sanitized = sanitizeString(joined, mode, config);
    ctx.options.onSanitize?.(fieldPath, value, sanitized);
    return sanitized;
  }

  // 'each' mode
  return value.map((item, index) => {
    ctx.path.push(String(index));
    const sanitized = sanitizeValue(item, ctx);
    ctx.path.pop();
    return sanitized;
  });
}

/**
 * Sanitize a plain object value
 */
export function sanitizeObjectValue(
  value: Record<string, unknown>,
  fieldPath: string,
  ctx: SanitizationContext,
): Record<string, unknown> {
  if (ctx.currentDepth >= ctx.options.maxDepth) {
    const error = new Error(
      `Maximum recursion depth (${ctx.options.maxDepth}) exceeded at path: ${fieldPath}`,
    );
    if (ctx.options.throwOnError) throw error;
    ctx.options.onError?.(error, fieldPath);
    return value;
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value)) {
    ctx.path.push(key);
    ctx.currentDepth++;
    sanitized[key] = sanitizeValue(val, ctx);
    ctx.currentDepth--;
    ctx.path.pop();
  }
  return sanitized;
}

/**
 * Sanitize a single value
 */
export function sanitizeValue(value: unknown, ctx: SanitizationContext): unknown {
  const fieldPath = ctx.path.join(".");

  try {
    const fieldConfig = getFieldConfig(fieldPath, ctx.options);

    // Check if field should be skipped
    if (shouldSkipField(fieldPath, fieldConfig, ctx)) {
      return value;
    }

    // Handle custom sanitizer
    if (fieldConfig?.mode === "custom" && fieldConfig.sanitizer) {
      return applyCustomSanitizer(value, fieldPath, fieldConfig.sanitizer, ctx);
    }

    // Determine mode and config
    const mode = fieldConfig?.mode || ctx.options.mode;
    const config = fieldConfig?.config || ctx.options.config;

    // Handle strings
    if (typeof value === "string") {
      return sanitizeStringValue(value, fieldPath, mode, config, ctx);
    }

    // Handle arrays
    if (Array.isArray(value)) {
      return sanitizeArrayValue(value, fieldPath, mode, config, ctx);
    }

    // Handle objects (deep sanitization)
    if (isPlainObject(value) && ctx.options.deep) {
      return sanitizeObjectValue(value, fieldPath, ctx);
    }

    // Return other types as-is (numbers, booleans, null, etc.)
    return value;
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    if (ctx.options.throwOnError) throw err;
    ctx.options.onError?.(err, fieldPath);
    return value;
  }
}

/**
 * Sanitize a request target (body, query, params, headers)
 */
export async function sanitizeTarget(
  target: Record<string, unknown>,
  options: SanitizationContext["options"],
): Promise<Record<string, unknown>> {
  const ctx: SanitizationContext = {
    options,
    currentDepth: 0,
    path: [],
  };

  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(target)) {
    ctx.path.push(key);
    sanitized[key] = sanitizeValue(value, ctx);
    ctx.path.pop();
  }

  return sanitized;
}
