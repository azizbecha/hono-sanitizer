# hono-sanitizer

> A flexible, production-ready middleware for [Hono](https://hono.dev) that sanitizes request data using [isomorphic-dompurify](https://www.npmjs.com/package/isomorphic-dompurify).

[![npm version](https://img.shields.io/npm/v/hono-sanitizer.svg)](https://www.npmjs.com/package/hono-sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

## Features

- 🛡️ **Secure by Default**: Strip malicious HTML/XSS from user input
- 🎯 **Flexible Targeting**: Sanitize body, query, params, or headers
- ⚙️ **Highly Configurable**: Whitelist, blacklist, per-field rules
- 🔧 **Custom Sanitizers**: Use your own sanitization logic
- 📦 **TypeScript First**: Full type safety and IntelliSense
- 🚀 **Zero Config**: Works out of the box with sensible defaults
- 🎨 **Rich Text Support**: Allow safe HTML with DOMPurify config
- 🌳 **Deep Sanitization**: Handle nested objects and arrays
- ⚡ **Production Ready**: Error handling, callbacks, and presets

## Installation

```bash
npm install hono-sanitizer
```

```bash
yarn add hono-sanitizer
```

```bash
pnpm add hono-sanitizer
```

## Quick Start

```typescript
import { Hono } from "hono";
import { sanitizer } from "hono-sanitizer";

const app = new Hono();

// Sanitize all request bodies (strips HTML by default)
app.use("*", sanitizer());

app.post("/message", async (c) => {
  const { message } = await c.req.json();
  // message is now sanitized and safe to store
  return c.json({ message });
});

export default app;
```

## Usage Examples

### Basic Usage

```typescript
import { sanitizer } from "hono-sanitizer";

// Strip all HTML from request body
app.use("*", sanitizer());

// POST { message: '<script>alert("xss")</script>Hello' }
// Result: { message: 'Hello' }
```

### Target Specific Request Parts

```typescript
// Sanitize body and query parameters
app.use(
  "*",
  sanitizer({
    targets: ["body", "query"],
  }),
);

// Sanitize everything
app.use(
  "*",
  sanitizer({
    targets: ["body", "query", "params", "headers"],
  }),
);
```

### Whitelist Specific Fields

```typescript
// Only sanitize specific fields
app.use(
  "*",
  sanitizer({
    whitelist: ["username", "message", "bio"],
    mode: "strict",
  }),
);
```

### Blacklist (Skip) Fields

```typescript
// Sanitize everything except richContent
app.use(
  "*",
  sanitizer({
    blacklist: ["richContent", "htmlBody"],
  }),
);
```

### Per-Field Configuration

```typescript
app.use(
  "*",
  sanitizer({
    fields: {
      // Strip all HTML from messages
      message: { mode: "strict" },

      // Allow safe HTML in descriptions
      description: {
        mode: "html",
        config: {
          ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "p", "br"],
          ALLOWED_ATTR: ["href", "target"],
        },
      },

      // Don't sanitize metadata
      metadata: { mode: "skip" },

      // Custom sanitizer
      username: {
        mode: "custom",
        sanitizer: (value) => String(value).toLowerCase().trim(),
      },
    },
  }),
);
```

### Using Presets

```typescript
import { sanitizer, presets } from "hono-sanitizer";

// Strict mode - strip all HTML
app.use("/api/comments/*", sanitizer(presets.strict));

// Rich text - allow safe HTML tags
app.use("/api/posts/*", sanitizer(presets.richText));

// Markdown - minimal HTML
app.use("/api/articles/*", sanitizer(presets.markdown));
```

### Route-Specific Rules

```typescript
// Different rules for different routes
app.use(
  "/api/posts/*",
  sanitizer({
    fields: {
      title: { mode: "strict" },
      content: {
        mode: "html",
        config: {
          ALLOWED_TAGS: ["p", "br", "strong", "em", "ul", "ol", "li", "h1", "h2"],
        },
      },
    },
  }),
);

app.use(
  "/api/comments/*",
  sanitizer({
    mode: "strict", // No HTML in comments
  }),
);
```

### Deep Object Sanitization

```typescript
app.use(
  "*",
  sanitizer({
    deep: true,
    maxDepth: 5,
    fields: {
      "user.bio": { mode: "html" },
      "user.email": { mode: "strict" },
    },
  }),
);

// POST { user: { bio: '<p>Hello</p>', email: 'test@example.com' } }
// Both nested fields are sanitized according to their rules
```

### Array Handling

```typescript
app.use(
  "*",
  sanitizer({
    arrays: "each", // Sanitize each array element (default)
  }),
);

// Other options:
// arrays: 'skip'  - Don't sanitize arrays
// arrays: 'join'  - Join array elements and sanitize as single string
```

### With Callbacks

```typescript
app.use(
  "*",
  sanitizer({
    onSanitize: (field, original, sanitized) => {
      if (original !== sanitized) {
        console.log(`Sanitized ${field}:`, { original, sanitized });
      }
    },
    onSkip: (field, value) => {
      console.log(`Skipped ${field}`);
    },
    onError: (error, field) => {
      console.error(`Error sanitizing ${field}:`, error);
    },
  }),
);
```

### Accessing Sanitized Data

```typescript
import { sanitizer, getSanitizedBody, getSanitizedQuery } from "hono-sanitizer";

app.use("*", sanitizer());

app.post("/message", async (c) => {
  // Method 1: Use helper functions
  const body = getSanitizedBody(c);
  const query = getSanitizedQuery(c);

  // Method 2: Regular request methods (data is already sanitized)
  const data = await c.req.json();

  return c.json({ body, query });
});
```

## API Reference

### `sanitizer(options?)`

Creates a Hono middleware that sanitizes request data.

#### Options

```typescript
type SanitizerOptions = {
  /** Which parts of the request to sanitize. Default: ['body'] */
  targets?: ("body" | "query" | "params" | "headers")[];

  /** Default sanitization mode. Default: 'strict' */
  mode?: "strict" | "html" | "skip" | "custom";

  /** Only sanitize these fields */
  whitelist?: string[];

  /** Sanitize all except these fields */
  blacklist?: string[];

  /** Per-field configuration */
  fields?: Record<string, FieldConfig>;

  /** Enable deep object sanitization. Default: true */
  deep?: boolean;

  /** Maximum recursion depth. Default: 10 */
  maxDepth?: number;

  /** Array handling strategy. Default: 'each' */
  arrays?: "skip" | "each" | "join";

  /** DOMPurify config for 'html' mode */
  config?: DOMPurifyConfig;

  /** Callback after sanitization */
  onSanitize?: (field: string, original: unknown, sanitized: unknown) => void;

  /** Callback when field is skipped */
  onSkip?: (field: string, value: unknown) => void;

  /** Callback on error */
  onError?: (error: Error, field: string) => void;

  /** Throw errors instead of logging. Default: false */
  throwOnError?: boolean;
};
```

#### FieldConfig

```typescript
type FieldConfig = {
  /** Sanitization mode for this field */
  mode: "strict" | "html" | "skip" | "custom";

  /** DOMPurify config (when mode is 'html') */
  config?: DOMPurifyConfig;

  /** Custom sanitizer function (when mode is 'custom') */
  sanitizer?: (value: unknown) => unknown;
};
```

### Sanitization Modes

- **`strict`**: Strip all HTML tags (safest, default)
- **`html`**: Allow safe HTML with DOMPurify configuration
- **`skip`**: Don't sanitize this field
- **`custom`**: Use a custom sanitizer function

### Helper Functions

```typescript
// Get sanitized data from context
getSanitizedBody<T>(c: Context): T | null
getSanitizedQuery<T>(c: Context): T | null
getSanitizedParams<T>(c: Context): T | null
getSanitizedHeaders<T>(c: Context): T | null
```

### Presets

```typescript
import { presets } from "hono-sanitizer";

presets.strict; // Strip all HTML from body, query, params
presets.richText; // Allow common HTML tags (blog posts)
presets.markdown; // Allow minimal HTML (markdown content)
presets.comments; // Very strict (user comments)
```

## Configuration Examples

### Blog Platform

```typescript
// Posts - allow rich formatting
app.use(
  "/api/posts/*",
  sanitizer({
    fields: {
      title: { mode: "strict" },
      content: {
        mode: "html",
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
      excerpt: { mode: "strict" },
      tags: { mode: "strict" },
    },
  }),
);

// Comments - no HTML allowed
app.use("/api/comments/*", sanitizer(presets.strict));
```

### User Registration

```typescript
app.use(
  "/api/auth/register",
  sanitizer({
    fields: {
      username: {
        mode: "custom",
        sanitizer: (value) => String(value).toLowerCase().trim().slice(0, 50),
      },
      email: {
        mode: "custom",
        sanitizer: (value) => String(value).toLowerCase().trim(),
      },
      password: { mode: "skip" }, // Don't sanitize passwords
      bio: { mode: "strict" },
    },
  }),
);
```

### E-commerce Product

```typescript
app.use(
  "/api/products/*",
  sanitizer({
    fields: {
      name: { mode: "strict" },
      description: {
        mode: "html",
        config: {
          ALLOWED_TAGS: ["p", "br", "ul", "ol", "li", "strong", "em"],
          ALLOWED_ATTR: [],
        },
      },
      price: { mode: "skip" }, // Number, not string
      tags: { mode: "strict" },
      metadata: { mode: "skip" }, // JSON data
    },
  }),
);
```

## Security Best Practices

1. **Always sanitize user input** before storing in database
2. **Use strict mode by default** - only allow HTML when necessary
3. **Validate data types** before sanitization (use Zod, Valibot, etc.)
4. **Sanitize at the edge** - as close to input as possible
5. **Don't trust sanitized data completely** - use parameterized queries
6. **Log sanitization events** for security monitoring
7. **Keep dependencies updated** - especially DOMPurify

### Example: Complete Security Setup

```typescript
import { Hono } from "hono";
import { sanitizer } from "hono-sanitizer";
import { z } from "zod";

const app = new Hono();

// 1. Sanitize input
app.use(
  "*",
  sanitizer({
    mode: "strict",
    onSanitize: (field, original, sanitized) => {
      if (original !== sanitized) {
        console.warn(`[Security] Sanitized ${field}`);
      }
    },
  }),
);

// 2. Validate with schema
const messageSchema = z.object({
  message: z.string().min(1).max(1000),
  username: z.string().min(3).max(50),
});

app.post("/message", async (c) => {
  const body = await c.req.json();

  // Validate
  const result = messageSchema.safeParse(body);
  if (!result.success) {
    return c.json({ error: "Invalid data" }, 400);
  }

  const { message, username } = result.data;

  // 3. Use parameterized queries (example with Drizzle)
  await db.insert(messages).values({
    message,
    username,
    createdAt: new Date(),
  });

  return c.json({ success: true });
});
```

## Performance Considerations

- Sanitization has minimal overhead for simple strings
- Deep object sanitization may impact performance with large payloads
- Use `maxDepth` to prevent deep recursion attacks
- Consider using `whitelist` for better performance on large objects
- Skip sanitization for trusted internal routes

## Error Handling

```typescript
app.use(
  "*",
  sanitizer({
    throwOnError: false, // Default: log errors without throwing
    onError: (error, field) => {
      // Log to monitoring service
      console.error(`Sanitization error in ${field}:`, error);
      // Send to error tracking (Sentry, etc.)
    },
  }),
);
```

## TypeScript Support

Full TypeScript support with type inference:

```typescript
import type { SanitizerOptions, FieldConfig } from "hono-sanitizer";

const config: SanitizerOptions = {
  targets: ["body", "query"],
  mode: "strict",
  fields: {
    username: { mode: "custom", sanitizer: (v) => String(v).toLowerCase() },
  },
};

app.use("*", sanitizer(config));
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) first.

## License

MIT © [Aziz Becha](https://github.com/azizbecha)

## Support

- 📖 [Documentation](https://github.com/azizbecha/hono-sanitizer)
- 🐛 [Issue Tracker](https://github.com/azizbecha/hono-sanitizer/issues)
- 💬 [Discussions](https://github.com/azizbecha/hono-sanitizer/discussions)

---

**Made with ❤️ for the Hono community**
