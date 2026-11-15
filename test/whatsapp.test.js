const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  WhatsAppError,
  createWhatsAppClient
} = require("../whatsapp");

const ACCESS_TOKEN = "test-access-token-never-log";
const PHONE_NUMBER_ID = "123456789012345";
const RECIPIENT = "12025550123";
const ENV = Object.freeze({
  WHATSAPP_ACCESS_TOKEN: ACCESS_TOKEN,
  WHATSAPP_PHONE_NUMBER_ID: PHONE_NUMBER_ID,
  WHATSAPP_API_VERSION: "v23.0",
  WHATSAPP_REQUEST_TIMEOUT_MS: "4321",
  WHATSAPP_DEFAULT_COUNTRY_CODE: "1"
});

function fixture({ env = {}, post } = {}) {
  const calls = [];
  const logs = [];
  const http = {
    async post(url, payload, options) {
      calls.push({ url, payload, options });
      return post
        ? post(url, payload, options)
        : { status: 200, data: { messages: [{ id: "  wamid.accepted-123  " }] } };
    }
  };
  const client = createWhatsAppClient({
    http,
    env: { ...ENV, ...env },
    logger: { error: (...args) => logs.push(args) }
  });
  return { client, calls, logs };
}

function request(overrides = {}) {
  return {
    to: "+1 (202) 555-0123",
    templateName: "order_created",
    language: "en_US",
    components: [{
      type: "body",
      parameters: [{ type: "text", text: "order-123" }]
    }],
    ...overrides
  };
}

test("generic client sends the exact Meta template request and returns the accepted ID", async () => {
  const f = fixture();

  assert.equal(f.client.isConfigured(), true);
  assert.equal(f.client.isTemplateValid("order_created", "en_US"), true);
  assert.deepEqual(await f.client.sendTemplate(request()), {
    messageId: "wamid.accepted-123"
  });

  assert.deepEqual(f.calls, [{
    url: `https://graph.facebook.com/v23.0/${PHONE_NUMBER_ID}/messages`,
    payload: {
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to: RECIPIENT,
      type: "template",
      template: {
        name: "order_created",
        language: { code: "en_US" },
        components: [{
          type: "body",
          parameters: [{ type: "text", text: "order-123" }]
        }]
      }
    },
    options: {
      headers: {
        Authorization: `Bearer ${ACCESS_TOKEN}`,
        "Content-Type": "application/json"
      },
      timeout: 4321,
      maxRedirects: 0
    }
  }]);
  assert.deepEqual(f.logs, []);
});

test("malformed configuration is rejected before HTTP", async (t) => {
  const cases = [
    ["missing token", { WHATSAPP_ACCESS_TOKEN: "" }],
    ["blank token", { WHATSAPP_ACCESS_TOKEN: "   " }],
    ["missing phone-number ID", { WHATSAPP_PHONE_NUMBER_ID: "" }],
    ["non-numeric phone-number ID", { WHATSAPP_PHONE_NUMBER_ID: "12/messages" }],
    ["leading-zero phone-number ID", { WHATSAPP_PHONE_NUMBER_ID: "0123" }],
    ["missing API version", { WHATSAPP_API_VERSION: "" }],
    ["malformed API version", { WHATSAPP_API_VERSION: "23.0" }],
    ["path-like API version", { WHATSAPP_API_VERSION: "v23.0/messages" }]
  ];

  for (const [name, env] of cases) {
    await t.test(name, async () => {
      const f = fixture({ env });
      assert.equal(f.client.isConfigured(), false);
      await assert.rejects(
        f.client.sendTemplate(request()),
        (err) => err instanceof WhatsAppError &&
          err.message === "WhatsApp Cloud API is not configured"
      );
      assert.equal(f.calls.length, 0);
      assert.equal(f.logs.length, 0);
    });
  }
});

test("malformed recipients and templates are rejected before HTTP", async (t) => {
  const cases = [
    ["missing recipient", { to: undefined }],
    ["numeric recipient", { to: 12025550123 }],
    ["short recipient", { to: "+1234567" }],
    ["recipient injection", { to: "+12025550123?x=1" }],
    ["local recipient without country code", { to: "2025550123" }, { WHATSAPP_DEFAULT_COUNTRY_CODE: "" }],
    ["missing template", { templateName: undefined }],
    ["uppercase template", { templateName: "Order_Created" }],
    ["spaced template", { templateName: "order created" }],
    ["path-like template", { templateName: "../order_created" }],
    ["malformed language", { language: "en-us" }],
    ["malformed language suffix", { language: "en_us" }],
    ["non-array components", { components: {} }]
  ];

  for (const [name, overrides, env] of cases) {
    await t.test(name, async () => {
      const f = fixture({ env });
      await assert.rejects(
        f.client.sendTemplate(request(overrides)),
        (err) => err instanceof WhatsAppError &&
          err.message === "Invalid WhatsApp template request"
      );
      assert.equal(f.calls.length, 0);
      assert.equal(f.logs.length, 0);
    });
  }
});

test("non-2xx and missing message IDs are not treated as accepted", async (t) => {
  const responses = [
    ["missing response", undefined],
    ["missing status", { data: { messages: [{ id: "wamid.value" }] } }],
    ["redirect", { status: 302, data: { messages: [{ id: "wamid.value" }] } }],
    ["client error", { status: 400, data: { messages: [{ id: "wamid.value" }] } }],
    ["missing data", { status: 200 }],
    ["missing ID", { status: 200, data: { messages: [{}] } }],
    ["blank ID", { status: 201, data: { messages: [{ id: "   " }] } }],
    ["numeric ID", { status: 200, data: { messages: [{ id: 123 }] } }]
  ];

  for (const [name, response] of responses) {
    await t.test(name, async () => {
      const f = fixture({ post: async () => response });
      await assert.rejects(
        f.client.sendTemplate(request()),
        (err) => err instanceof WhatsAppError &&
          err.message === "WhatsApp did not accept the template message" &&
          err.status === response?.status &&
          err.unknownDelivery === false
      );
      assert.equal(f.calls.length, 1);
      assert.equal(f.logs.length, 0);
    });
  }
});

test("provider rejection logs only sanitized status, code, and timeout metadata", async () => {
  const privateAddress = "12 Private Street";
  const f = fixture({ post: async (_url, payload) => {
    const err = new Error(`${ACCESS_TOKEN} ${RECIPIENT} ${privateAddress}`);
    err.code = "ERR_BAD_REQUEST";
    err.config = {
      headers: { Authorization: `Bearer ${ACCESS_TOKEN}` },
      data: payload
    };
    err.response = {
      status: 400,
      data: {
        error: {
          code: 132000,
          message: `${privateAddress} ${JSON.stringify(payload)}`
        }
      }
    };
    throw err;
  } });

  await assert.rejects(
    f.client.sendTemplate(request({
      components: [{
        type: "body",
        parameters: [{ type: "text", text: privateAddress }]
      }]
    })),
    (err) => err instanceof WhatsAppError &&
      err.message === "WhatsApp Cloud API request failed" &&
      err.status === 400 &&
      err.code === 132000 &&
      err.timedOut === false &&
      err.unknownDelivery === false
  );

  assert.deepEqual(f.logs, [[
    "WhatsApp Cloud API request failed",
    { status: 400, code: 132000, timedOut: false }
  ]]);
  const visible = JSON.stringify(f.logs);
  for (const secret of [ACCESS_TOKEN, RECIPIENT, privateAddress, "order_created", "Authorization"]) {
    assert.equal(visible.includes(secret), false, `log leaked ${secret}`);
  }
});

test("timeout is marked as timed out with unknown delivery and logs no request data", async () => {
  const privateValue = "private-template-payload";
  const f = fixture({ post: async (_url, payload) => {
    const err = new Error(`${ACCESS_TOKEN} ${RECIPIENT} ${privateValue}`);
    err.code = "ETIMEDOUT";
    err.config = {
      headers: { Authorization: `Bearer ${ACCESS_TOKEN}` },
      data: payload
    };
    throw err;
  } });

  await assert.rejects(
    f.client.sendTemplate(request({
      components: [{ type: "body", parameters: [{ type: "text", text: privateValue }] }]
    })),
    (err) => err instanceof WhatsAppError &&
      err.status === undefined &&
      err.code === undefined &&
      err.timedOut === true &&
      err.unknownDelivery === true
  );

  assert.deepEqual(f.logs, [[
    "WhatsApp Cloud API request failed",
    { status: undefined, code: undefined, timedOut: true }
  ]]);
  const visible = JSON.stringify(f.logs);
  for (const secret of [ACCESS_TOKEN, RECIPIENT, privateValue, "template", "Authorization"]) {
    assert.equal(visible.includes(secret), false, `log leaked ${secret}`);
  }
});

test("132001 identifies the rejected template and language without logging private data", async () => {
  const privateValue = "private-order-address-and-otp";
  const f = fixture({ post: async (_url, payload) => {
    const err = new Error(`${ACCESS_TOKEN} ${RECIPIENT} ${privateValue}`);
    err.response = {
      status: 404,
      data: { error: { code: 132001, message: err.message, error_data: { details: JSON.stringify(payload) } } }
    };
    throw err;
  } });

  await assert.rejects(f.client.sendTemplate(request({
    templateName: "order_notification",
    language: "en",
    components: [{ type: "body", parameters: [{ type: "text", text: privateValue }] }]
  })), (err) => err instanceof WhatsAppError &&
    err.code === 132001 && err.status === 404 &&
    err.reason === "template_not_found" && err.unknownDelivery === false);

  assert.equal(f.calls.length, 1);
  assert.deepEqual(f.logs[0][1], {
    status: 404,
    code: 132001,
    timedOut: false,
    reason: "template_not_found",
    templateName: "order_notification",
    language: "en",
    hint: "Use the exact approved template name and language from the sending number's WhatsApp Business Account."
  });
  const visible = JSON.stringify(f.logs);
  for (const secret of [ACCESS_TOKEN, RECIPIENT, privateValue, "error_data", "components"]) {
    assert.equal(visible.includes(secret), false, `log leaked ${secret}`);
  }
});
