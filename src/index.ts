/**
 * hono-sanitizer
 *
 * A flexible, production-ready middleware for Hono that sanitizes request data
 * using isomorphic-dompurify with extensive configuration options.
 *
 * @packageDocumentation
 */

import type { Context, MiddlewareHandler } from "hono";
import type {
	RequestTarget,
	SanitizerOptions,
	DOMPurifyConfig,
	SanitizationMode,
	ArrayStrategy,
	FieldConfig,
} from " ./types";

/**
 * Preset configurations for common use cases
 */
export const presets = {
	/**
	 * Strict mode - strip all HTML
	 */
	strict: {
		mode: "strict" as const,
		targets: ["body", "query", "params"] as RequestTarget[],
	},

	/**
	 * Rich text mode - allow safe HTML tags
	 */
	richText: {
		mode: "html" as const,
		targets: ["body"] as RequestTarget[],
		config: {
			ALLOWED_TAGS: [
				"p",
				"br",
				"strong",
				"em",
				"u",
				"h1",
				"h2",
				"h3",
				"h4",
				"h5",
				"h6",
				"ul",
				"ol",
				"li",
				"a",
				"blockquote",
				"code",
				"pre",
			],
			ALLOWED_ATTR: ["href", "target", "rel"],
		},
	},

	/**
	 * Markdown mode - allow minimal HTML
	 */
	markdown: {
		mode: "html" as const,
		targets: ["body"] as RequestTarget[],
		config: {
			ALLOWED_TAGS: ["p", "br", "strong", "em", "code", "pre", "a"],
			ALLOWED_ATTR: ["href"],
		},
	},

	/**
	 * Comments mode - very strict
	 */
	comments: {
		mode: "strict" as const,
		targets: ["body"] as RequestTarget[],
		deep: true,
	},
} as const;

// ============================================================================
// Main Middleware
// ============================================================================

/**
 * Create a sanitizer middleware for Hono
 *
 * @param options - Sanitization options
 * @returns Hono middleware handler
 *
 * @example
 * ```typescript
 * import { Hono } from 'hono'
 * import { sanitizer } from 'hono-sanitizer'
 *
 * const app = new Hono()
 *
 * // Basic usage
 * app.use('*', sanitizer())
 *
 * // With options
 * app.use('*', sanitizer({
 *   targets: ['body', 'query'],
 *   mode: 'strict',
 *   whitelist: ['username', 'message']
 * }))
 * ```
 */
export function sanitizer(options: SanitizerOptions = {}): MiddlewareHandler {
	// Merge with defaults
	const mergedOptions: SanitizationContext["options"] = {
		...DEFAULT_OPTIONS,
		...options,
		// Ensure arrays and other reference types aren't accidentally shared
		targets: options.targets || DEFAULT_OPTIONS.targets,
	};

	return async (c: Context, next) => {
		const targets = mergedOptions.targets;

		try {
			// Sanitize body
			if (targets.includes("body")) {
				const contentType = c.req.header("content-type") || "";

				if (contentType.includes("application/json")) {
					try {
						const body = await c.req.json();
						if (isPlainObject(body)) {
							const sanitized = await sanitizeTarget(
								body,
								"body",
								mergedOptions,
							);
							// Override the parsed body
							c.req.raw.clone = () => {
								const init = {
									method: c.req.method,
									headers: c.req.raw.headers,
									body: JSON.stringify(sanitized),
								};
								return new Request(c.req.url, init);
							};
							// Store sanitized body for retrieval
							c.req.__sanitizedBody = sanitized;
						}
					} catch (error) {
						// Not JSON or already consumed, skip
						console.error(error);
					}
				}
			}

			// Sanitize query
			if (targets.includes("query")) {
				const query = c.req.query();
				if (Object.keys(query).length > 0) {
					const sanitized = await sanitizeTarget(
						query as Record<string, unknown>,
						"query",
						mergedOptions,
					);
					c.req.__sanitizedQuery = sanitized;
				}
			}

			// Sanitize params
			if (targets.includes("params")) {
				const params = c.req.param();
				if (Object.keys(params).length > 0) {
					const sanitized = await sanitizeTarget(
						params as Record<string, unknown>,
						"params",
						mergedOptions,
					);
					c.req.__sanitizedParams = sanitized;
				}
			}

			// Sanitize headers
			if (targets.includes("headers")) {
				const headers: Record<string, string> = {};
				c.req.raw.headers.forEach((value, key) => {
					headers[key] = value;
				});
				if (Object.keys(headers).length > 0) {
					const sanitized = await sanitizeTarget(
						headers,
						"headers",
						mergedOptions,
					);
					c.req.__sanitizedHeaders = sanitized;
				}
			}
		} catch (error) {
			const err = error instanceof Error ? error : new Error(String(error));
			if (mergedOptions.throwOnError) throw err;
			mergedOptions.onError?.(err, "middleware");
		}

		await next();
	};
}

/**
 * Helper function to get sanitized body from request
 * Use this in your route handlers to access sanitized data
 *
 * @example
 * ```typescript
 * app.post('/message', async (c) => {
 *   const body = getSanitizedBody(c)
 *   // body is sanitized
 * })
 * ```
 */
export function getSanitizedBody<T = Record<string, unknown>>(
	c: Context,
): T | null {
	return c.req.__sanitizedBody || null;
}

/**
 * Helper function to get sanitized query from request
 */
export function getSanitizedQuery<T = Record<string, unknown>>(
	c: Context,
): T | null {
	return c.req.__sanitizedQuery || null;
}

/**
 * Helper function to get sanitized params from request
 */
export function getSanitizedParams<T = Record<string, unknown>>(
	c: Context,
): T | null {
	return c.req.__sanitizedParams || null;
}

/**
 * Helper function to get sanitized headers from request
 */
export function getSanitizedHeaders<T = Record<string, string>>(
	c: Context,
): T | null {
	return c.req.__sanitizedHeaders || null;
}

export type {
	DOMPurifyConfig,
	RequestTarget,
	SanitizationMode,
	ArrayStrategy,
	FieldConfig,
	SanitizerOptions,
};
