export type DOMPurifyConfig = {
  ALLOWED_TAGS?: string[];
  ALLOWED_ATTR?: string[];
  ALLOW_DATA_ATTR?: boolean;
  FORBID_TAGS?: string[];
  FORBID_ATTR?: string[];
  ALLOW_ARIA_ATTR?: boolean;
  ALLOW_UNKNOWN_PROTOCOLS?: boolean;
  SAFE_FOR_TEMPLATES?: boolean;
  WHOLE_DOCUMENT?: boolean;
  RETURN_DOM?: boolean;
  RETURN_DOM_FRAGMENT?: boolean;
  RETURN_TRUSTED_TYPE?: boolean;
  FORCE_BODY?: boolean;
  SANITIZE_DOM?: boolean;
  KEEP_CONTENT?: boolean;
  IN_PLACE?: boolean;
  USE_PROFILES?: {
    html?: boolean;
    svg?: boolean;
    svgFilters?: boolean;
    mathMl?: boolean;
  };
};

/**
 * Request targets that can be sanitized
 */
export type RequestTarget = "body" | "query" | "params" | "headers";

/**
 * Sanitization mode for fields
 */
export type SanitizationMode = "strict" | "html" | "skip" | "custom";

/**
 * Array handling strategy
 */
export type ArrayStrategy = "skip" | "each" | "join";

/**
 * Per-field sanitization configuration
 */
export type FieldConfig = {
  /** Sanitization mode for this field */
  mode: SanitizationMode;
  /** DOMPurify config (only used when mode is 'html') */
  config?: DOMPurifyConfig;
  /** Custom sanitizer function (only used when mode is 'custom') */
  sanitizer?: (value: unknown) => unknown;
};

/**
 * Main sanitizer options
 */
export type SanitizerOptions = {
  /** Which parts of the request to sanitize. Default: ['body'] */
  targets?: RequestTarget[];

  /** Default sanitization mode for all fields. Default: 'strict' */
  mode?: SanitizationMode;

  /** Only sanitize these fields (if specified, blacklist is ignored) */
  whitelist?: string[];

  /** Sanitize all fields except these */
  blacklist?: string[];

  /** Per-field configuration. Overrides mode, whitelist, and blacklist */
  fields?: Record<string, FieldConfig>;

  /** Enable deep object sanitization. Default: true */
  deep?: boolean;

  /** Maximum recursion depth for nested objects. Default: 10 */
  maxDepth?: number;

  /** How to handle arrays. Default: 'each' */
  arrays?: ArrayStrategy;

  /** DOMPurify config for 'html' mode. Default: undefined */
  config?: DOMPurifyConfig;

  /** Called after a field is sanitized */
  onSanitize?: (field: string, original: unknown, sanitized: unknown) => void;

  /** Called when a field is skipped */
  onSkip?: (field: string, value: unknown) => void;

  /** Called when an error occurs during sanitization */
  onError?: (error: Error, field: string) => void;

  /** Whether to throw errors or log them. Default: false */
  throwOnError?: boolean;
};

/**
 * Internal sanitization context
 */
export type SanitizationContext = {
  options: Required<
    Omit<
      SanitizerOptions,
      "whitelist" | "blacklist" | "fields" | "config" | "onSanitize" | "onSkip" | "onError"
    >
  > & {
    whitelist?: string[];
    blacklist?: string[];
    fields?: Record<string, FieldConfig>;
    config?: DOMPurifyConfig;
    onSanitize?: (field: string, original: unknown, sanitized: unknown) => void;
    onSkip?: (field: string, value: unknown) => void;
    onError?: (error: Error, field: string) => void;
  };
  currentDepth: number;
  path: string[];
};
