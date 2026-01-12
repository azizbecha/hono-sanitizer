import type { SanitizerOptions } from "../types";

export const DEFAULT_OPTIONS: Required<
	Omit<
		SanitizerOptions,
		| "whitelist"
		| "blacklist"
		| "fields"
		| "config"
		| "onSanitize"
		| "onSkip"
		| "onError"
	>
> = {
	targets: ["body"],
	mode: "strict",
	deep: true,
	maxDepth: 10,
	arrays: "each",
	throwOnError: false,
};
