import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import {
  sanitizer,
  presets,
  getSanitizedBody,
  getSanitizedQuery,
  getSanitizedParams,
  getSanitizedHeaders,
} from "../src/index";

describe("sanitizer", () => {
  describe("Basic Functionality", () => {
    it("should strip HTML tags in strict mode by default", async () => {
      const app = new Hono();
      app.use("*", sanitizer());
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: '<script>alert("xss")</script>Hello',
          name: "<b>John</b>",
        }),
      });

      const data = await res.json();
      expect(data.message).toBe("Hello");
      expect(data.name).toBe("John");
    });

    it("should sanitize nested objects", async () => {
      const app = new Hono();
      app.use("*", sanitizer({ deep: true }));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user: {
            name: "<script>evil</script>Alice",
            profile: {
              bio: "<img src=x onerror=alert(1)>Hello",
            },
          },
        }),
      });

      const data = await res.json();
      expect(data.user.name).toBe("Alice");
      expect(data.user.profile.bio).toBe("Hello");
    });

    it('should sanitize arrays when arrays mode is "each"', async () => {
      const app = new Hono();
      app.use("*", sanitizer({ arrays: "each" }));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tags: ["<script>xss</script>tag1", "<b>tag2</b>", "tag3"],
        }),
      });

      const data = await res.json();
      expect(data.tags).toEqual(["tag1", "tag2", "tag3"]);
    });

    it('should skip arrays when arrays mode is "skip"', async () => {
      const app = new Hono();
      app.use("*", sanitizer({ arrays: "skip" }));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tags: ["<script>xss</script>tag1", "<b>tag2</b>"],
        }),
      });

      const data = await res.json();
      expect(data.tags).toEqual(["<script>xss</script>tag1", "<b>tag2</b>"]);
    });
  });

  describe("Target Selection", () => {
    it("should only sanitize body by default", async () => {
      const app = new Hono();
      app.use("*", sanitizer());
      app.get("/test", async (c) => {
        const query = getSanitizedQuery(c);
        return c.json({ query });
      });

      const res = await app.request("/test?message=<script>xss</script>hello");
      const data = await res.json();

      // Query should not be sanitized (body only by default)
      expect(data.query).toBeNull();
    });

    it("should sanitize query when specified", async () => {
      const app = new Hono();
      app.use("*", sanitizer({ targets: ["query"] }));
      app.get("/test", async (c) => {
        const query = getSanitizedQuery(c);
        return c.json({ query });
      });

      const res = await app.request("/test?message=<script>xss</script>hello");
      const data = await res.json();

      expect(data.query.message).toBe("hello");
    });

    it("should sanitize multiple targets", async () => {
      const app = new Hono();
      app.use("*", sanitizer({ targets: ["body", "query"] }));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        const query = getSanitizedQuery(c);
        return c.json({ body, query });
      });

      const res = await app.request("/test?name=<b>Admin</b>", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: "<script>xss</script>Hello" }),
      });

      const data = await res.json();
      expect(data.body.message).toBe("Hello");
      expect(data.query.name).toBe("Admin");
    });
  });

  describe("Whitelist", () => {
    it("should only sanitize whitelisted fields", async () => {
      const app = new Hono();
      app.use("*", sanitizer({ whitelist: ["message"] }));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "<script>xss</script>Hello",
          name: "<b>John</b>",
        }),
      });

      const data = await res.json();
      expect(data.message).toBe("Hello");
      expect(data.name).toBe("<b>John</b>"); // Not in whitelist, not sanitized
    });
  });

  describe("Blacklist", () => {
    it("should skip blacklisted fields", async () => {
      const app = new Hono();
      app.use("*", sanitizer({ blacklist: ["richContent"] }));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "<script>xss</script>Hello",
          richContent: "<p>Keep this <b>HTML</b></p>",
        }),
      });

      const data = await res.json();
      expect(data.message).toBe("Hello");
      expect(data.richContent).toBe("<p>Keep this <b>HTML</b></p>");
    });
  });

  describe("Field Configuration", () => {
    it("should use per-field configuration", async () => {
      const app = new Hono();
      app.use(
        "*",
        sanitizer({
          fields: {
            message: { mode: "strict" },
            description: {
              mode: "html",
              config: {
                ALLOWED_TAGS: ["b", "i", "p"],
                ALLOWED_ATTR: [],
              },
            },
            metadata: { mode: "skip" },
          },
        }),
      );
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "<b>Hello</b><script>xss</script>",
          description: "<p>Keep <b>this</b></p><script>remove</script>",
          metadata: "<script>keep everything</script>",
        }),
      });

      const data = await res.json();
      expect(data.message).toBe("Hello");
      expect(data.description).toBe("<p>Keep <b>this</b></p>");
      expect(data.metadata).toBe("<script>keep everything</script>");
    });

    it("should support custom sanitizer functions", async () => {
      const app = new Hono();
      app.use(
        "*",
        sanitizer({
          fields: {
            username: {
              mode: "custom",
              sanitizer: (value) => String(value).toLowerCase().trim(),
            },
          },
        }),
      );
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: "  ADMIN  ",
        }),
      });

      const data = await res.json();
      expect(data.username).toBe("admin");
    });
  });

  describe("HTML Mode", () => {
    it("should allow safe HTML tags in html mode", async () => {
      const app = new Hono();
      app.use(
        "*",
        sanitizer({
          mode: "html",
          config: {
            ALLOWED_TAGS: ["b", "i", "p"],
            ALLOWED_ATTR: [],
          },
        }),
      );
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: "<p>Hello <b>World</b></p><script>xss</script>",
        }),
      });

      const data = await res.json();
      expect(data.content).toBe("<p>Hello <b>World</b></p>");
    });
  });

  describe("Presets", () => {
    it("should work with strict preset", async () => {
      const app = new Hono();
      app.use("*", sanitizer(presets.strict));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "<script>xss</script><b>Hello</b>",
        }),
      });

      const data = await res.json();
      expect(data.message).toBe("Hello");
    });

    it("should work with richText preset", async () => {
      const app = new Hono();
      app.use("*", sanitizer(presets.richText as any));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: "<p>Hello <strong>World</strong></p><script>xss</script>",
        }),
      });

      const data = await res.json();
      expect(data.content).toContain("<p>");
      expect(data.content).toContain("<strong>");
      expect(data.content).not.toContain("<script>");
    });
  });

  describe("Deep Sanitization", () => {
    it("should respect maxDepth setting", async () => {
      const app = new Hono();
      const onError = vi.fn();
      app.use("*", sanitizer({ deep: true, maxDepth: 2, onError }));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          level1: {
            level2: {
              level3: {
                message: "<script>xss</script>deep",
              },
            },
          },
        }),
      });

      const _data = await res.json();
      expect(onError).toHaveBeenCalled();
    });

    it("should sanitize deeply nested structures", async () => {
      const app = new Hono();
      app.use("*", sanitizer({ deep: true, maxDepth: 5 }));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user: {
            profile: {
              details: {
                bio: "<script>xss</script>Hello",
              },
            },
          },
        }),
      });

      const data = await res.json();
      expect(data.user.profile.details.bio).toBe("Hello");
    });
  });

  describe("Callbacks", () => {
    it("should call onSanitize when field is sanitized", async () => {
      const onSanitize = vi.fn();
      const app = new Hono();
      app.use("*", sanitizer({ onSanitize }));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "<script>xss</script>Hello",
        }),
      });

      expect(onSanitize).toHaveBeenCalled();
      const call = onSanitize.mock.calls[0];
      expect(call[0]).toBe("message");
      expect(call[1]).toBe("<script>xss</script>Hello");
      expect(call[2]).toBe("Hello");
    });

    it("should call onSkip when field is skipped", async () => {
      const onSkip = vi.fn();
      const app = new Hono();
      app.use("*", sanitizer({ blacklist: ["metadata"], onSkip }));
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          metadata: "<script>keep</script>",
        }),
      });

      expect(onSkip).toHaveBeenCalled();
      const call = onSkip.mock.calls[0];
      expect(call[0]).toBe("metadata");
    });

    it("should call onError when error occurs", async () => {
      const onError = vi.fn();
      const app = new Hono();
      app.use(
        "*",
        sanitizer({
          fields: {
            test: {
              mode: "custom",
              sanitizer: () => {
                throw new Error("Test error");
              },
            },
          },
          onError,
          throwOnError: false,
        }),
      );
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body || {});
      });

      await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test: "value" }),
      });

      expect(onError).toHaveBeenCalled();
      const call = onError.mock.calls[0];
      expect(call[0]).toBeInstanceOf(Error);
      expect(call[0].message).toBe("Test error");
    });
  });

  describe("Error Handling", () => {
    it("should not throw errors by default", async () => {
      const app = new Hono();
      app.use(
        "*",
        sanitizer({
          fields: {
            test: {
              mode: "custom",
              sanitizer: () => {
                throw new Error("Test error");
              },
            },
          },
        }),
      );
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body || {});
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test: "value" }),
      });

      expect(res.status).toBe(200);
    });

    it("should throw errors when throwOnError is true", async () => {
      const app = new Hono();
      app.onError((err, c) => {
        return c.text(err.message, 500);
      });
      app.post(
        "/test",
        sanitizer({
          fields: {
            test: {
              mode: "custom",
              sanitizer: () => {
                throw new Error("Test error");
              },
            },
          },
          throwOnError: true,
        }),
        (c) => c.text("OK"),
      );

      const res = await app.request("/test", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ test: "value" }),
      });

      expect(res.status).toBe(500);
      expect(await res.text()).toBe("Test error");
    });
  });

  describe("Type Preservation", () => {
    it("should preserve non-string types", async () => {
      const app = new Hono();
      app.use("*", sanitizer());
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          count: 42,
          active: true,
          data: null,
          tags: ["tag1", "tag2"],
        }),
      });

      const data = await res.json();
      expect(data.count).toBe(42);
      expect(data.active).toBe(true);
      expect(data.data).toBe(null);
      expect(data.tags).toEqual(["tag1", "tag2"]);
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty objects", async () => {
      const app = new Hono();
      app.use("*", sanitizer());
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body || {});
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      const data = await res.json();
      expect(data).toEqual({});
    });

    it("should handle empty strings", async () => {
      const app = new Hono();
      app.use("*", sanitizer());
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: "" }),
      });

      const data = await res.json();
      expect(data.message).toBe("");
    });

    it("should handle special characters", async () => {
      const app = new Hono();
      app.use("*", sanitizer());
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "Hello & goodbye © 2024",
        }),
      });

      const data = await res.json();
      expect(data.message).toContain("&");
      expect(data.message).toContain("©");
    });

    it("should handle unicode characters", async () => {
      const app = new Hono();
      app.use("*", sanitizer());
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json(body);
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "Hello 世界 🌍",
        }),
      });

      const data = await res.json();
      expect(data.message).toBe("Hello 世界 🌍");
    });
  });

  describe("Helper Functions", () => {
    it("getSanitizedBody should return null when not sanitized", async () => {
      const app = new Hono();
      app.post("/test", async (c) => {
        const body = getSanitizedBody(c);
        return c.json({ body });
      });

      const res = await app.request("/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: "test" }),
      });

      const data = await res.json();
      expect(data.body).toBe(null);
    });

    it("all helper functions should work together", async () => {
      const app = new Hono();
      app.post(
        "/:id",
        sanitizer({ targets: ["body", "query", "params", "headers"] }),
        async (c) => {
          return c.json({
            body: getSanitizedBody(c),
            query: getSanitizedQuery(c),
            params: getSanitizedParams(c),
            headers: getSanitizedHeaders(c),
          });
        },
      );

      const res = await app.request("/123?search=<b>test</b>", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Custom": "<script>xss</script>header",
        },
        body: JSON.stringify({ message: "<b>body</b>" }),
      });

      const data = await res.json();
      expect(data.body).toBeTruthy();
      expect(data.query).toBeTruthy();
      expect(data.params).toBeTruthy();
      expect(data.headers).toBeTruthy();
    });
  });
});
