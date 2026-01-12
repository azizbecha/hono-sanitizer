import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { sanitizer, getSanitizedBody } from "../src/index";

describe("Edge Cases and Security Tests", () => {
	describe("XSS Attack Vectors", () => {
		it("should block script tag variations", async () => {
			const app = new Hono();
			app.use("*", sanitizer());
			app.post("/test", async (c) => {
				const body = getSanitizedBody(c);
				return c.json(body);
			});

			const xssPayloads = [
				"<script>alert(1)</script>",
				"<SCRIPT>alert(1)</SCRIPT>",
				"<script>alert(String.fromCharCode(88,83,83))</script>",
				"<img src=x onerror=alert(1)>",
				"<svg onload=alert(1)>",
				'<iframe src="javascript:alert(1)">',
				"<body onload=alert(1)>",
				"<input onfocus=alert(1) autofocus>",
				"<select onfocus=alert(1) autofocus>",
				"<textarea onfocus=alert(1) autofocus>",
				"<marquee onstart=alert(1)>",
			];

			for (const payload of xssPayloads) {
				const res = await app.request("/test", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ input: payload }),
				});

				const data = await res.json();
				expect(data.input).not.toContain("<script");
				expect(data.input).not.toContain("onerror");
				expect(data.input).not.toContain("onload");
				expect(data.input).not.toContain("onfocus");
				expect(data.input).not.toContain("javascript:");
			}
		});

		it("should handle encoded XSS attempts", async () => {
			const app = new Hono();
			app.use("*", sanitizer());
			app.post("/test", async (c) => {
				const body = getSanitizedBody(c);
				return c.json(body);
			});

			const encodedPayloads = [
				"&lt;script&gt;alert(1)&lt;/script&gt;",
				"&#60;script&#62;alert(1)&#60;/script&#62;",
				"&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
			];

			for (const payload of encodedPayloads) {
				const res = await app.request("/test", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ input: payload }),
				});

				const data = await res.json();
				// Should not be executable
				expect(data.input).toContain("alert");
				expect(data.input).toMatch(
					/(&lt;|&#60;|&#x3c;)script(&gt;|&#62;|&#x3e;)/i,
				);
			}
		});
	});

	describe("SQL Injection Protection", () => {
		it("should preserve SQL-like strings (sanitization is for XSS, not SQLi)", async () => {
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
					query: "SELECT * FROM users WHERE id = 1 OR 1=1",
				}),
			});

			const data = await res.json();
			// SQL injection strings should be preserved (use parameterized queries for SQL safety)
			expect(data.query).toBe("SELECT * FROM users WHERE id = 1 OR 1=1");
		});
	});

	describe("Large Payloads", () => {
		it("should handle large nested objects", async () => {
			const app = new Hono();
			app.use("*", sanitizer({ deep: true, maxDepth: 20 }));
			app.post("/test", async (c) => {
				const body = getSanitizedBody(c);
				return c.json(body);
			});

			// Create deeply nested object
			const createNestedObject = (depth: number) => {
				if (depth === 0) {
					return { value: "<script>xss</script>deep" };
				}
				return { nested: createNestedObject(depth - 1) };
			};

			const payload = createNestedObject(10);

			const res = await app.request("/test", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(payload),
			});

			const data = await res.json();

			// Navigate to deep value
			let current = data;
			for (let i = 0; i < 10; i++) {
				current = current.nested;
			}

			expect(current.value).toBe("deep");
		});

		it("should handle large arrays", async () => {
			const app = new Hono();
			app.use("*", sanitizer({ arrays: "each" }));
			app.post("/test", async (c) => {
				const body = getSanitizedBody(c);
				return c.json(body);
			});

			const largeArray = Array(100).fill("<script>xss</script>item");

			const res = await app.request("/test", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ items: largeArray }),
			});

			const data = await res.json();
			expect(data.items).toHaveLength(100);
			expect(data.items.every((item: string) => item === "item")).toBe(true);
		});
	});

	describe("Special Characters and Encoding", () => {
		it("should preserve legitimate HTML entities", async () => {
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
					text: "Price: $100 &amp; free shipping",
				}),
			});

			const data = await res.json();
			expect(data.text).toContain("&amp;");
		});

		it("should handle mixed content", async () => {
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
					mixed: "Text with <b>bold</b> and <script>evil</script> content",
				}),
			});

			const data = await res.json();
			expect(data.mixed).toBe("Text with bold and  content");
		});
	});

	describe("Boundary Conditions", () => {
		it("should handle null values", async () => {
			const app = new Hono();
			app.use("*", sanitizer());
			app.post("/test", async (c) => {
				const body = getSanitizedBody(c);
				return c.json(body);
			});

			const res = await app.request("/test", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ value: null }),
			});

			const data = await res.json();
			expect(data.value).toBe(null);
		});

		it("should handle undefined values", async () => {
			const app = new Hono();
			app.use("*", sanitizer());
			app.post("/test", async (c) => {
				const body = getSanitizedBody(c);
				return c.json(body);
			});

			const res = await app.request("/test", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ defined: "value" }),
			});

			const data = await res.json();
			expect(data.undefined).toBeUndefined();
		});

		it("should handle very long strings", async () => {
			const app = new Hono();
			app.use("*", sanitizer());
			app.post("/test", async (c) => {
				const body = getSanitizedBody(c);
				return c.json(body);
			});

			const longString = "a".repeat(10000) + "<script>xss</script>";

			const res = await app.request("/test", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ text: longString }),
			});

			const data = await res.json();
			expect(data.text).toHaveLength(10000);
			expect(data.text).not.toContain("<script>");
		});
	});

	describe("Concurrent Requests", () => {
		it("should handle multiple simultaneous requests", async () => {
			const app = new Hono();
			app.use("*", sanitizer());
			app.post("/test", async (c) => {
				const body = getSanitizedBody(c);
				return c.json(body);
			});

			const requests = Array(10)
				.fill(null)
				.map((_, i) =>
					app.request("/test", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({
							id: i,
							message: `<script>xss${i}</script>message${i}`,
						}),
					}),
				);

			const responses = await Promise.all(requests);
			const data = await Promise.all(responses.map((r) => r.json()));

			data.forEach((item, i) => {
				expect(item.id).toBe(i);
				expect(item.message).toBe(`message${i}`);
			});
		});
	});

	describe("Content Types", () => {
		it("should gracefully handle non-JSON content", async () => {
			const app = new Hono();
			app.use("*", sanitizer());
			app.post("/test", async (c) => {
				const body = getSanitizedBody(c);
				return c.json({ body });
			});

			const res = await app.request("/test", {
				method: "POST",
				headers: { "Content-Type": "text/plain" },
				body: "plain text",
			});

			const _data = await res.json();
			// Should not crash, body might be null or empty
			expect(res.status).toBe(200);
		});
	});

	describe("Path-based Field Configuration", () => {
		it("should match nested field paths correctly", async () => {
			const app = new Hono();
			app.use(
				"*",
				sanitizer({
					fields: {
						"user.profile.bio": {
							mode: "html",
							config: {
								ALLOWED_TAGS: ["b", "i"],
								ALLOWED_ATTR: [],
							},
						},
						"user.profile.status": { mode: "strict" },
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
					user: {
						profile: {
							bio: "<b>Bold</b> text <script>xss</script>",
							status: "<b>Active</b>",
						},
					},
				}),
			});

			const data = await res.json();
			expect(data.user.profile.bio).toBe("<b>Bold</b> text ");
			expect(data.user.profile.status).toBe("Active");
		});
	});

	describe("Array Join Mode", () => {
		it("should join and sanitize arrays", async () => {
			const app = new Hono();
			app.use("*", sanitizer({ arrays: "join" }));
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
			expect(typeof data.tags).toBe("string");
			expect(data.tags).toBe("tag1 tag2 tag3");
		});
	});

	describe("Real-world Scenarios", () => {
		it("should sanitize a blog post submission", async () => {
			const app = new Hono();
			app.use(
				"*",
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
									"ul",
									"ol",
									"li",
									"a",
								],
								ALLOWED_ATTR: ["href"],
							},
						},
						excerpt: { mode: "strict" },
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
					title: "<script>xss</script>My Blog Post",
					content: "<p>Hello <strong>world</strong>!</p><script>evil</script>",
					excerpt: "<b>Short</b> description",
					author: "John Doe",
				}),
			});

			const data = await res.json();
			expect(data.title).toBe("My Blog Post");
			expect(data.content).toContain("<p>");
			expect(data.content).toContain("<strong>");
			expect(data.content).not.toContain("<script>");
			expect(data.excerpt).toBe("Short description");
			expect(data.author).toBe("John Doe");
		});

		it("should sanitize user registration data", async () => {
			const app = new Hono();
			app.use(
				"*",
				sanitizer({
					fields: {
						username: {
							mode: "custom",
							sanitizer: (value) =>
								String(value)
									.toLowerCase()
									.replace(/[^a-z0-9_]/g, ""),
						},
						email: {
							mode: "custom",
							sanitizer: (value) => String(value).toLowerCase().trim(),
						},
						password: { mode: "skip" },
						bio: { mode: "strict" },
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
					username: "Admin<script>User</script>123",
					email: "  USER@EXAMPLE.COM  ",
					password: "P@ssw0rd!<script>",
					bio: "<b>Hello</b> World",
				}),
			});

			const data = await res.json();
			expect(data.username).toBe("adminscriptuserscript123");
			expect(data.email).toBe("user@example.com");
			expect(data.password).toBe("P@ssw0rd!<script>"); // Not sanitized
			expect(data.bio).toBe("Hello World");
		});
	});
});
