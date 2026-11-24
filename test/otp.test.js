const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const { normalizePhone, createOtpHandlers, registerOtpRoutes } = require("../otp");

const NOW = Date.parse("2026-11-11T12:00:00Z");
const PHONE = "12025550123";
const CODE = "123456";
const HASH = bcrypt.hashSync(CODE, 4);
const ENV = {
  WHATSAPP_ACCESS_TOKEN: "test-token-not-a-real-credential",
  WHATSAPP_PHONE_NUMBER_ID: "123456789012345",
  WHATSAPP_API_VERSION: "v23.0",
  WHATSAPP_TEMPLATE_NAME: "test_login_code",
  WHATSAPP_TEMPLATE_LANGUAGE: "en_US"
};

function response() {
  const res = new EventEmitter();
  res.statusCode = 200;
  res.headers = {};
  res.headersSent = false;
  res.writableEnded = false;
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.setHeader = (name, value) => {
    res.headers[name.toLowerCase()] = value;
  };
  res.getHeader = (name) => res.headers[name.toLowerCase()];
  res.send = res.json = (body) => {
    res.body = body;
    res.headersSent = true;
    res.writableEnded = true;
    res.emit("finish");
    return res;
  };
  return res;
}

function record(overrides = {}) {
  return {
    id: "stored-otp-id",
    phone: PHONE,
    otp: HASH,
    expires_at: new Date(NOW + 300000),
    created_at: new Date(NOW - 61000),
    is_verified: 0,
    ...overrides
  };
}

function database(rows = [], now = () => NOW) {
  const db = {
    rows: rows.map((row) => ({ ...row })),
    calls: [],
    async query(sql, params) {
      sql = sql.replace(/\s+/g, " ").trim();
      db.calls.push({ sql, params });

      if (sql.startsWith("SELECT")) {
        let matches = db.rows.filter((row) => row.phone === params[0]);
        if (sql.includes("is_verified = 0")) {
          matches = matches.filter((row) => row.is_verified === 0);
        }
        matches.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        return [matches.slice(0, 1).map((row) => ({ ...row }))];
      }
      if (sql === "DELETE FROM phone_otps WHERE phone = ?") {
        db.rows = db.rows.filter((row) => row.phone !== params[0]);
        return [{ affectedRows: 1 }];
      }
      if (sql === "DELETE FROM phone_otps WHERE id = ?") {
        db.rows = db.rows.filter((row) => row.id !== params[0]);
        return [{ affectedRows: 1 }];
      }
      if (sql.startsWith("INSERT INTO phone_otps")) {
        const [id, phone, otp, expires_at] = params;
        db.rows.push({ id, phone, otp, expires_at, created_at: new Date(now()), is_verified: 0 });
        return [{ affectedRows: 1 }];
      }
      if (sql.startsWith("UPDATE phone_otps SET is_verified = 1")) {
        const row = db.rows.find((item) =>
          item.id === params[0] && item.is_verified === 0 && item.expires_at > params[1]
        );
        if (row) row.is_verified = 1;
        return [{ affectedRows: row ? 1 : 0 }];
      }
      throw new Error(`Unexpected test query: ${sql}`);
    }
  };
  return db;
}

function fixture({ env = {}, rows = [], post, now = () => NOW } = {}) {
  const db = database(rows, now);
  const calls = [];
  const logs = [];
  const http = {
    async post(url, payload, options) {
      calls.push({ url, payload, options });
      return post ? post(url, payload, options) : {
        status: 200,
        data: { messages: [{ id: "wamid.test-message" }] }
      };
    }
  };
  const options = {
    db, http, env: { ...ENV, ...env }, now,
    logger: { error: (...args) => logs.push(args) }
  };
  return { db, calls, logs, options, ...createOtpHandlers(options) };
}

async function invoke(handler, body) {
  const res = response();
  await handler({ body }, res);
  return res;
}

function routes(options) {
  const registered = new Map();
  const app = {
    get: () => false,
    post: (path, ...handlers) => registered.set(path, handlers)
  };
  registerOtpRoutes(app, options);

  return {
    registered,
    async request(path, body, ip = "192.0.2.1") {
      const req = { app, body, ip, headers: {}, socket: { remoteAddress: ip } };
      const res = response();
      for (const middleware of registered.get(path)) {
        let continued = false;
        let failure;
        await middleware(req, res, (err) => {
          continued = true;
          failure = err;
        });
        if (failure) throw failure;
        if (!continued) break;
      }
      await new Promise((resolve) => setImmediate(resolve));
      return res;
    }
  };
}

test("normalizes international and explicitly configured ten-digit local numbers", () => {
  assert.equal(normalizePhone(" +1 (202) 555-0123 "), PHONE);
  assert.equal(normalizePhone(PHONE), PHONE);
  assert.equal(normalizePhone("98765 43210", "91"), "919876543210");
  assert.equal(normalizePhone("09876543210", "91"), "919876543210");
  assert.equal(normalizePhone("+91 9876543210", "91"), "919876543210");
  assert.equal(normalizePhone("919876543210", "91"), "919876543210");
  assert.equal(normalizePhone("+1234567890"), "1234567890");
  assert.equal(normalizePhone("+123456789012345"), "123456789012345");
  assert.equal(normalizePhone("9876543210"), null);
});

test("rejects malformed phone types, characters, lengths, and country codes", () => {
  for (const phone of [undefined, null, 12025550123, {}, [], "", "   ", "abc", "++12025550123", "+01234567890", "0012025550123", "+1234567", "+1234567890123456", "+12025550123 ext 4", "1".repeat(100)]) {
    assert.equal(normalizePhone(phone), null, String(phone));
  }
  for (const countryCode of ["+91", "0", "091", "1234", "abc"]) {
    assert.equal(normalizePhone("9876543210", countryCode), null);
  }
});

test("rejects invalid send input before touching storage or HTTP", async () => {
  const f = fixture();
  for (const body of [undefined, null, {}, { phone: 1234567890 }, { phone: "invalid" }]) {
    const res = await invoke(f.sendOtp, body);
    assert.equal(res.statusCode, 400);
  }
  assert.equal(f.db.calls.length, 0);
  assert.equal(f.calls.length, 0);
});

test("rejects missing or malformed WhatsApp configuration before database changes", async () => {
  const invalid = [
    { WHATSAPP_ACCESS_TOKEN: "" },
    { WHATSAPP_PHONE_NUMBER_ID: "" },
    { WHATSAPP_PHONE_NUMBER_ID: "../messages" },
    { WHATSAPP_API_VERSION: undefined },
    { WHATSAPP_API_VERSION: "23.0" },
    { WHATSAPP_TEMPLATE_NAME: "" },
    { WHATSAPP_TEMPLATE_NAME: "Not Approved" },
    { WHATSAPP_TEMPLATE_LANGUAGE: "invalid language" }
  ];
  for (const env of invalid) {
    const f = fixture({ env });
    const res = await invoke(f.sendOtp, { phone: PHONE });
    assert.equal(res.statusCode, 503, JSON.stringify(env));
    assert.equal(f.db.calls.length, 0);
    assert.equal(f.calls.length, 0);
    assert.equal(JSON.stringify(f.logs).includes(ENV.WHATSAPP_ACCESS_TOKEN), false);
  }
});

test("sends a secure OTP using the exact WhatsApp copy-code template payload", async (t) => {
  const random = t.mock.method(crypto, "randomInt", (minimum, maximum) => {
    assert.equal(minimum, 100000);
    assert.equal(maximum, 1000000);
    return 729184;
  });
  const f = fixture();
  const res = await invoke(f.sendOtp, { phone: "+1 (202) 555-0123" });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, { success: true, message: "OTP submitted to WhatsApp" });
  assert.equal(random.mock.callCount(), 1);
  assert.equal(f.calls.length, 1);
  const { url, payload, options } = f.calls[0];
  assert.equal(url, "https://graph.facebook.com/v23.0/123456789012345/messages");
  assert.deepEqual(payload, {
    messaging_product: "whatsapp",
    recipient_type: "individual",
    to: PHONE,
    type: "template",
    template: {
      name: "test_login_code",
      language: { code: "en_US" },
      components: [
        { type: "body", parameters: [{ type: "text", text: "729184" }] },
        { type: "button", sub_type: "url", index: "0", parameters: [{ type: "text", text: "729184" }] }
      ]
    }
  });
  assert.deepEqual(options, {
    headers: { Authorization: `Bearer ${ENV.WHATSAPP_ACCESS_TOKEN}`, "Content-Type": "application/json" },
    timeout: 10000,
    maxRedirects: 0
  });
  const [stored] = f.db.rows;
  assert.match(stored.id, /^[0-9a-f-]{36}$/);
  assert.equal(stored.phone, PHONE);
  assert.equal(stored.is_verified, 0);
  assert.match(stored.otp, /^\$2[aby]\$10\$/);
  assert.notEqual(stored.otp, "729184");
  assert.equal(await bcrypt.compare("729184", stored.otp), true);
  assert.equal(stored.expires_at.getTime(), NOW + 300000);
  assert.equal(JSON.stringify(res.body).includes("729184"), false);
  assert.equal(f.logs.length, 0);
});

test("honors configured expiry, timeout, template language, and local phone identity", async () => {
  const f = fixture({ env: {
    OTP_EXPIRY_MINUTES: "2",
    WHATSAPP_REQUEST_TIMEOUT_MS: "4500",
    WHATSAPP_TEMPLATE_LANGUAGE: "en_GB",
    WHATSAPP_DEFAULT_COUNTRY_CODE: "91"
  } });
  assert.equal((await invoke(f.sendOtp, { phone: "9876543210" })).statusCode, 200);
  assert.equal(f.db.rows[0].expires_at.getTime(), NOW + 120000);
  assert.equal(f.calls[0].options.timeout, 4500);
  assert.equal(f.calls[0].payload.template.language.code, "en_GB");
  const code = f.calls[0].payload.template.components[0].parameters[0].text;
  assert.match(code, /^[1-9]\d{5}$/);
  const res = await invoke(f.verifyOtp, { phone: "+91 98765-43210", otp: code });
  assert.deepEqual(res.body, { success: true, message: "Phone verified" });
  assert.equal(f.db.rows[0].phone, normalizePhone("9876543210", "91"));
});

test("invalid numeric tuning values use safe defaults", async () => {
  const f = fixture({ env: {
    OTP_EXPIRY_MINUTES: "-5",
    WHATSAPP_REQUEST_TIMEOUT_MS: "999999999999999"
  } });
  await invoke(f.sendOtp, { phone: PHONE });
  assert.equal(f.db.rows[0].expires_at.getTime(), NOW + 300000);
  assert.equal(f.calls[0].options.timeout, 10000);
});

test("cooldown returns a rounded Retry-After and does not send or replace the code", async () => {
  const f = fixture({ rows: [record({ created_at: new Date(NOW - 10001) })] });
  const res = await invoke(f.sendOtp, { phone: PHONE });
  assert.equal(res.statusCode, 429);
  assert.equal(res.getHeader("Retry-After"), "50");
  assert.match(res.body.message, /Wait 50 seconds/);
  assert.equal(f.calls.length, 0);
  assert.equal(f.db.calls.length, 1);
  assert.equal(f.db.rows[0].id, "stored-otp-id");
});

test("resending is allowed exactly at the configured cooldown boundary", async () => {
  const f = fixture({
    env: { OTP_RESEND_COOLDOWN: "30" },
    rows: [record({ created_at: new Date(NOW - 30000) })]
  });
  const res = await invoke(f.sendOtp, { phone: PHONE });
  assert.equal(res.statusCode, 200);
  assert.equal(f.db.rows.length, 1);
  assert.notEqual(f.db.rows[0].id, "stored-otp-id");
});

test("non-2xx or malformed provider responses invalidate only the inserted attempt", async (t) => {
  const cases = [
    ["missing response", undefined],
    ["missing status", { data: { messages: [{ id: "wamid.test" }] } }],
    ["redirect", { status: 302, data: { messages: [{ id: "wamid.test" }] } }],
    ["error status", { status: 400, data: { messages: [{ id: "wamid.test" }] } }],
    ["missing ID", { status: 200, data: { messages: [{}] } }],
    ["empty ID", { status: 200, data: { messages: [{ id: " " }] } }],
    ["numeric ID", { status: 200, data: { messages: [{ id: 123 }] } }]
  ];
  for (const [name, result] of cases) {
    await t.test(name, async () => {
      const f = fixture({ post: async () => result });
      const res = await invoke(f.sendOtp, { phone: PHONE });
      assert.equal(res.statusCode, 502);
      assert.equal(f.db.rows.length, 0);
      const inserted = f.db.calls.find((call) => call.sql.startsWith("INSERT"));
      assert.deepEqual(f.db.calls.at(-1), {
        sql: "DELETE FROM phone_otps WHERE id = ?", params: [inserted.params[0]]
      });
    });
  }
});

test("provider rejections and timeouts are cleaned up without leaking secrets", async (t) => {
  for (const code of ["ECONNABORTED", "ETIMEDOUT", "ERR_BAD_REQUEST"]) {
    await t.test(code, async () => {
      const f = fixture({ post: async (_url, payload) => {
        const otp = payload.template.components[0].parameters[0].text;
        const err = new Error(`private ${ENV.WHATSAPP_ACCESS_TOKEN} ${PHONE} ${otp}`);
        err.code = code;
        err.config = { headers: { Authorization: ENV.WHATSAPP_ACCESS_TOKEN }, data: payload };
        err.response = { status: 400, data: { error: { code: 132000, message: err.message } } };
        throw err;
      } });
      const res = await invoke(f.sendOtp, { phone: PHONE });
      assert.equal(res.statusCode, 502);
      assert.equal(f.db.rows.length, 0);
      const visible = JSON.stringify([res.body, f.logs]);
      assert.equal(visible.includes(ENV.WHATSAPP_ACCESS_TOKEN), false);
      assert.equal(visible.includes(PHONE), false);
      assert.equal(visible.includes(f.calls[0].payload.template.components[0].parameters[0].text), false);
      assert.deepEqual(f.logs[0][1], {
        status: 400, code: 132000, timedOut: code !== "ERR_BAD_REQUEST"
      });
    });
  }
});

test("failure cleanup preserves a newer OTP inserted during provider submission", async () => {
  const f = fixture({ post: async () => {
    f.db.rows.push(record({ id: "newer-attempt" }));
    throw new Error("provider unavailable");
  } });
  assert.equal((await invoke(f.sendOtp, { phone: PHONE })).statusCode, 502);
  assert.deepEqual(f.db.rows.map((row) => row.id), ["newer-attempt"]);
});

test("database failure during provider cleanup is logged safely", async () => {
  const f = fixture({ post: async () => { throw new Error("provider unavailable"); } });
  const query = f.db.query;
  f.db.query = async (sql, params) => {
    if (sql.includes("WHERE id = ?")) throw new Error("private database details");
    return query(sql, params);
  };
  const res = await invoke(f.sendOtp, { phone: PHONE });
  assert.equal(res.statusCode, 502);
  assert.equal(f.db.rows.length, 1);
  assert.equal(f.logs.length, 2);
  assert.equal(JSON.stringify([res.body, f.logs]).includes("private database details"), false);
});

test("invalid verification input never queries the database", async () => {
  const f = fixture();
  for (const body of [undefined, {}, { phone: PHONE }, { phone: PHONE, otp: 123456 }, { phone: PHONE, otp: "12345" }, { phone: PHONE, otp: "1234567" }, { phone: PHONE, otp: "abcdef" }, { phone: [], otp: CODE }]) {
    assert.equal((await invoke(f.verifyOtp, body)).statusCode, 400);
  }
  assert.equal(f.db.calls.length, 0);
});

test("a valid code is marked verified once without extending expiry", async () => {
  const f = fixture({ rows: [record()] });
  const res = await invoke(f.verifyOtp, { phone: "+1 202-555-0123", otp: ` ${CODE} ` });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, { success: true, message: "Phone verified" });
  assert.equal(f.db.rows[0].is_verified, 1);
  assert.equal(f.db.rows[0].expires_at.getTime(), NOW + 300000);
  assert.match(f.db.calls[1].sql, /WHERE id = \? AND is_verified = 0 AND expires_at > \?/);
  assert.equal((await invoke(f.verifyOtp, { phone: PHONE, otp: CODE })).statusCode, 400);
});

test("wrong, missing, and previously verified codes are rejected", async () => {
  for (const rows of [[], [record({ is_verified: 1 })], [record()]]) {
    const f = fixture({ rows });
    const res = await invoke(f.verifyOtp, { phone: PHONE, otp: "000000" });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.message, "Invalid OTP");
    assert.equal(f.db.calls.some((call) => call.sql.startsWith("UPDATE")), false);
  }
});

test("expired, boundary-expired, and invalid expiry timestamps are rejected", async () => {
  for (const expires_at of [new Date(NOW - 1), new Date(NOW), "invalid-date"]) {
    const f = fixture({ rows: [record({ expires_at })] });
    const res = await invoke(f.verifyOtp, { phone: PHONE, otp: CODE });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.message, "OTP expired");
    assert.equal(f.db.calls.length, 1);
  }
});

test("a code that expires during bcrypt comparison cannot be marked verified", async () => {
  let reads = 0;
  const f = fixture({ rows: [record()], now: () => reads++ === 0 ? NOW : NOW + 300000 });
  const res = await invoke(f.verifyOtp, { phone: PHONE, otp: CODE });
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.message, "Invalid or expired OTP");
  assert.equal(f.db.rows[0].is_verified, 0);
});

test("database failures return generic errors for send and verify", async () => {
  for (const handler of ["sendOtp", "verifyOtp"]) {
    const f = fixture();
    f.db.query = async () => { throw new Error("private DB credentials"); };
    const res = await invoke(f[handler], { phone: PHONE, otp: CODE });
    assert.equal(res.statusCode, 500);
    assert.deepEqual(res.body, { message: "Server error" });
    assert.equal(f.calls.length, 0);
    assert.equal(JSON.stringify(f.logs).includes("private DB credentials"), false);
  }
});

test("registers the existing routes and limits send requests per IP", async () => {
  const f = fixture({ env: { OTP_SEND_MAX_REQUESTS: "2" } });
  const api = routes(f.options);
  assert.deepEqual([...api.registered.keys()], ["/api/send-otp", "/api/verify-otp"]);
  for (let i = 0; i < 2; i++) {
    assert.equal((await api.request("/api/send-otp", {})).statusCode, 400);
  }
  const blocked = await api.request("/api/send-otp", {});
  assert.equal(blocked.statusCode, 429);
  assert.ok(Number(blocked.getHeader("Retry-After")) > 0);
  assert.ok(blocked.getHeader("RateLimit"));
  assert.equal(blocked.getHeader("X-RateLimit-Limit"), undefined);
  assert.equal((await api.request("/api/send-otp", {}, "192.0.2.2")).statusCode, 400);
});

test("phone verification limits aggregate equivalent numbers across IPs", async () => {
  const f = fixture({ env: { OTP_VERIFY_MAX_ATTEMPTS: "2" } });
  const api = routes(f.options);
  assert.equal((await api.request("/api/verify-otp", { phone: PHONE, otp: CODE }, "192.0.2.1")).statusCode, 400);
  assert.equal((await api.request("/api/verify-otp", { phone: "+1 (202) 555-0123", otp: CODE }, "192.0.2.2")).statusCode, 400);
  assert.equal((await api.request("/api/verify-otp", { phone: PHONE, otp: CODE }, "192.0.2.3")).statusCode, 429);
  assert.equal(f.db.calls.length, 2);
  assert.equal((await api.request("/api/verify-otp", { phone: "12025550124", otp: CODE }, "192.0.2.3")).statusCode, 400);
});

test("IP verification limits aggregate failures across different phones", async () => {
  const f = fixture({ env: { OTP_VERIFY_IP_MAX_ATTEMPTS: "2", OTP_VERIFY_MAX_ATTEMPTS: "10" } });
  const api = routes(f.options);
  for (const phone of [PHONE, "12025550124"]) {
    assert.equal((await api.request("/api/verify-otp", { phone, otp: CODE })).statusCode, 400);
  }
  assert.equal((await api.request("/api/verify-otp", { phone: "12025550125", otp: CODE })).statusCode, 429);
  assert.equal(f.db.calls.length, 2);
  assert.equal((await api.request("/api/verify-otp", { phone: "12025550125", otp: CODE }, "192.0.2.2")).statusCode, 400);
});

test("successful verifications do not consume the failed-attempt limits", async () => {
  const f = fixture({ env: { OTP_VERIFY_MAX_ATTEMPTS: "1", OTP_VERIFY_IP_MAX_ATTEMPTS: "1" }, rows: [record()] });
  const api = routes(f.options);
  for (let i = 0; i < 3; i++) {
    f.db.rows = [record({ id: `fresh-code-${i}` })];
    assert.equal((await api.request("/api/verify-otp", { phone: PHONE, otp: CODE })).statusCode, 200);
  }
  f.db.rows = [record()];
  assert.equal((await api.request("/api/verify-otp", { phone: PHONE, otp: "000000" })).statusCode, 400);
  assert.equal((await api.request("/api/verify-otp", { phone: PHONE, otp: CODE })).statusCode, 429);
});

test("malformed verification phones use a safe IPv6 limiter fallback", async () => {
  const f = fixture({ env: { OTP_VERIFY_MAX_ATTEMPTS: "1" } });
  const api = routes(f.options);
  assert.equal((await api.request("/api/verify-otp", { phone: {}, otp: CODE }, "2001:db8::1")).statusCode, 400);
  assert.equal((await api.request("/api/verify-otp", { phone: {}, otp: CODE }, "2001:db8::2")).statusCode, 429);
  assert.equal(f.db.calls.length, 0);
});
