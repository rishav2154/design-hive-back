const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {
  WhatsAppError
} = require("../whatsapp");
const {
  ADMIN_KIND,
  CUSTOMER_KIND,
  parseAddress,
  formatAddress,
  formatItems,
  formatMoney,
  buildAdminComponents,
  buildCustomerComponents,
  createDedupeKey,
  createOrderNotificationService
} = require("../order-notifications");

const NOW = Date.parse("2026-01-02T16:04:05.000Z");
const ORDER_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_ORDER_ID = "22222222-2222-4222-8222-222222222222";
const ADMIN_PHONE = "12025550199";
const CUSTOMER_PHONE = "919876543210";
const ACCESS_TOKEN = "test-access-token-never-log";
const PRIVATE_ADDRESS = "221B Private Street";
const BASE_ENV = Object.freeze({
  WHATSAPP_ACCESS_TOKEN: ACCESS_TOKEN,
  WHATSAPP_ADMIN_PHONE: "+1 (202) 555-0199",
  WHATSAPP_ADMIN_ORDER_TEMPLATE_NAME: "admin_order_created",
  WHATSAPP_ADMIN_ORDER_TEMPLATE_LANGUAGE: "en_US",
  WHATSAPP_CUSTOMER_CONFIRMATION_ENABLED: "true",
  WHATSAPP_CUSTOMER_ORDER_TEMPLATE_NAME: "customer_order_created",
  WHATSAPP_CUSTOMER_ORDER_TEMPLATE_LANGUAGE: "en_US",
  WHATSAPP_DEFAULT_COUNTRY_CODE: "91",
  WHATSAPP_NOTIFICATION_BATCH_SIZE: "10",
  WHATSAPP_NOTIFICATION_CLAIM_TIMEOUT_MINUTES: "10",
  WHATSAPP_ORDER_CURRENCY: "INR",
  WHATSAPP_ORDER_TIMEZONE: "UTC"
});

function textValues(components) {
  return components[0].parameters.map((parameter) => parameter.text);
}

function completeOrder(overrides = {}) {
  return {
    id: ORDER_ID,
    created_at: "2026-01-02T16:04:05.000Z",
    customer_name: "Fallback Customer",
    customer_phone: CUSTOMER_PHONE,
    customer_email: "ada@example.test",
    customer_whatsapp_consent: true,
    items: [
      { product_name: "Phone Case", quantity: 2, price: 12.5 },
      { name: "Screen Guard", quantity: "1", price: "3" }
    ],
    final_amount: 28,
    payment_method: "online",
    payment_status: "paid",
    payment_id: "pay_shared_123",
    address: {
      full_name: "Ada Lovelace",
      phone: "+44 20 7946 0958",
      address_line1: "221B Baker Street",
      address_line2: "Flat 2",
      city: "London",
      state: "Greater London",
      pincode: "NW1"
    },
    ...overrides
  };
}

function validWhatsApp(overrides = {}) {
  const calls = [];
  return {
    calls,
    isConfigured: () => true,
    isTemplateValid: (name, language) =>
      /^[a-z0-9_]+$/.test(name) && /^[a-z]{2,3}(?:_[A-Z]{2})?$/.test(language),
    async sendTemplate(request) {
      calls.push(request);
      if (overrides.sendTemplate) return overrides.sendTemplate(request);
      return { messageId: "wamid.meta-accepted" };
    },
    ...overrides
  };
}

function createLogger() {
  const logs = [];
  return {
    logs,
    logger: { error: (...args) => logs.push(args) }
  };
}

class EnqueueConnection {
  constructor() {
    this.calls = [];
    this.rows = [];
    this.dedupeKeys = new Set();
  }

  async query(sql, params) {
    const normalized = sql.replace(/\s+/g, " ").trim();
    this.calls.push({ sql: normalized, params });
    assert.match(normalized, /^INSERT IGNORE INTO whatsapp_notification_outbox /);

    const dedupeKey = params[6];
    if (this.dedupeKeys.has(dedupeKey)) return [{ affectedRows: 0 }];
    this.dedupeKeys.add(dedupeKey);
    this.rows.push({
      id: params[0],
      order_id: params[1],
      notification_kind: params[2],
      recipient: params[3],
      template_name: params[4],
      template_language: params[5],
      dedupe_key: dedupeKey,
      payload: params[7],
      status: "pending"
    });
    return [{ affectedRows: 1 }];
  }
}

class OutboxDatabase {
  constructor(rows = []) {
    this.rows = rows.map((row) => ({ ...row }));
    this.calls = [];
  }

  async query(sql, params = []) {
    const normalized = sql.replace(/\s+/g, " ").trim();
    this.calls.push({ sql: normalized, params });

    if (normalized.includes("last_error_code = 'stale_claim'")) {
      const cutoff = NOW - params[0] * 60 * 1000;
      let affectedRows = 0;
      for (const row of this.rows) {
        if (row.status === "processing" &&
            new Date(row.claimed_at).getTime() < cutoff) {
          row.status = "unknown";
          row.last_error_code = "stale_claim";
          affectedRows += 1;
        }
      }
      return [{ affectedRows }];
    }

    if (normalized.includes("SET status = 'processing'")) {
      const candidates = this.rows
        .filter((row) => row.status === "pending" &&
          new Date(row.available_at).getTime() <= NOW)
        .sort((left, right) =>
          new Date(left.created_at).getTime() - new Date(right.created_at).getTime());
      const row = candidates[0];
      if (!row) return [{ affectedRows: 0 }];
      row.status = "processing";
      row.claim_token = params[0];
      row.claimed_at = new Date(NOW);
      row.attempt_count = (row.attempt_count || 0) + 1;
      return [{ affectedRows: 1 }];
    }

    if (normalized.startsWith("SELECT id, order_id, notification_kind")) {
      const row = this.rows.find((candidate) =>
        candidate.claim_token === params[0] && candidate.status === "processing");
      return [row ? [{
        id: row.id,
        order_id: row.order_id,
        notification_kind: row.notification_kind,
        recipient: row.recipient,
        template_name: row.template_name,
        template_language: row.template_language,
        payload: row.payload
      }] : []];
    }

    if (normalized.includes("SET status = ?, meta_message_id = ?")) {
      const [status, messageId, errorCode, sentStatus, id] = params;
      assert.equal(sentStatus, status);
      const row = this.rows.find((candidate) =>
        candidate.id === id && candidate.status === "processing");
      if (!row) return [{ affectedRows: 0 }];
      row.status = status;
      row.meta_message_id = messageId;
      row.last_error_code = errorCode;
      if (status === "sent") row.sent_at = new Date(NOW);
      row.claim_token = null;
      return [{ affectedRows: 1 }];
    }

    throw new Error(`Unexpected fake DB query: ${normalized}`);
  }
}

function pendingEvent(overrides = {}) {
  const order = completeOrder({
    address: {
      full_name: "Private Customer",
      phone: CUSTOMER_PHONE,
      address_line1: PRIVATE_ADDRESS,
      city: "Secret City",
      state: "Secret State",
      pincode: "000000"
    }
  });
  return {
    id: "notification-1",
    order_id: ORDER_ID,
    notification_kind: ADMIN_KIND,
    recipient: ADMIN_PHONE,
    template_name: "admin_order_created",
    template_language: "en_US",
    payload: JSON.stringify({
      order_id: order.id,
      created_at: order.created_at,
      customer_name: order.customer_name,
      customer_phone: order.customer_phone,
      customer_email: order.customer_email,
      items: order.items,
      final_amount: order.final_amount,
      payment_method: order.payment_method,
      payment_status: order.payment_status,
      address: order.address
    }),
    status: "pending",
    attempt_count: 0,
    available_at: new Date(NOW - 1000),
    created_at: new Date(NOW - 2000),
    claimed_at: null,
    claim_token: null,
    ...overrides
  };
}

function serviceFixture({ rows = [], env = {}, whatsapp, db } = {}) {
  const database = db || new OutboxDatabase(rows);
  const wa = whatsapp || validWhatsApp();
  const { logs, logger } = createLogger();
  const service = createOrderNotificationService({
    db: database,
    whatsapp: wa,
    env: { ...BASE_ENV, ...env },
    logger,
    now: () => new Date(NOW)
  });
  return { service, db: database, whatsapp: wa, logs, logger };
}

test("formatter includes UUID, zoned date, customer fields, every item, total, payment, and object address", () => {
  const order = completeOrder();
  const payload = { ...order, order_id: order.id };
  const env = {
    WHATSAPP_ORDER_CURRENCY: "USD",
    WHATSAPP_ORDER_TIMEZONE: "Asia/Kolkata"
  };

  assert.deepEqual(textValues(buildAdminComponents(payload, env)), [
    ORDER_ID,
    "2 Jan 2026, 09:34 pm",
    "Ada Lovelace",
    "+44 20 7946 0958",
    "ada@example.test",
    "Phone Case x 2 @ USD 12.50; Screen Guard x 1 @ USD 3.00",
    "USD 28.00",
    "online / paid",
    "221B Baker Street, Flat 2, London, Greater London, NW1"
  ]);
  assert.deepEqual(textValues(buildCustomerComponents(payload, env)), [
    ORDER_ID,
    "Phone Case x 2 @ USD 12.50; Screen Guard x 1 @ USD 3.00",
    "USD 28.00",
    "online / paid",
    "221B Baker Street, Flat 2, London, Greater London, NW1"
  ]);
});

test("formatter accepts a JSON address string with the same output", () => {
  const objectOrder = completeOrder();
  const stringOrder = completeOrder({ address: JSON.stringify(objectOrder.address) });
  const env = {
    WHATSAPP_ORDER_CURRENCY: "EUR",
    WHATSAPP_ORDER_TIMEZONE: "UTC"
  };

  assert.deepEqual(
    buildAdminComponents(stringOrder, env),
    buildAdminComponents(objectOrder, env)
  );
  assert.deepEqual(
    buildCustomerComponents(stringOrder, env),
    buildCustomerComponents(objectOrder, env)
  );
  assert.deepEqual(parseAddress(stringOrder.address), objectOrder.address);
  assert.equal(formatAddress(stringOrder.address),
    "221B Baker Street, Flat 2, London, Greater London, NW1");
});

test("formatter uses safe placeholders for missing and malformed fields", () => {
  const expectedAdmin = [
    "Not provided",
    "Not provided",
    "Not provided",
    "Not provided",
    "Not provided",
    "No items",
    "INR 0.00",
    "Not provided / Not provided",
    "Not provided"
  ];
  assert.deepEqual(textValues(buildAdminComponents({ address: "{bad-json" }, {
    WHATSAPP_ORDER_CURRENCY: "",
    WHATSAPP_ORDER_TIMEZONE: "UTC"
  })), expectedAdmin);
  assert.deepEqual(textValues(buildCustomerComponents({}, {})), [
    "Not provided",
    "No items",
    "INR 0.00",
    "Not provided / Not provided",
    "Not provided"
  ]);
  assert.deepEqual(parseAddress("{bad-json"), {});
  assert.equal(formatAddress([]), "Not provided");
  assert.equal(formatItems(null), "No items");
  assert.equal(formatMoney("not-a-number", "GBP"), "GBP 0.00");
});

test("invalid timezone falls back to an ISO date and configured currency is honored", () => {
  const order = completeOrder({
    items: [{ product_name: "Case", quantity: "bad", price: null }],
    final_amount: "19.5"
  });
  const values = textValues(buildAdminComponents(order, {
    WHATSAPP_ORDER_TIMEZONE: "Not/A_Timezone",
    WHATSAPP_ORDER_CURRENCY: "JPY"
  }));

  assert.equal(values[1], "2026-01-02T16:04:05.000Z");
  assert.equal(values[5], "Case x 0 @ JPY 0.00");
  assert.equal(values[6], "JPY 19.50");
});

test("enqueue writes an admin event and a separately consent-gated customer event", async () => {
  const connection = new EnqueueConnection();
  const { service, logs } = serviceFixture();
  const result = await service.enqueueForOrder(connection, completeOrder({
    customer_phone: "98765 43210"
  }));

  assert.deepEqual(result, { adminQueued: true, customerQueued: true });
  assert.equal(connection.rows.length, 2);
  assert.deepEqual(connection.rows.map((row) => row.notification_kind), [
    ADMIN_KIND,
    CUSTOMER_KIND
  ]);
  assert.deepEqual(connection.rows.map((row) => row.recipient), [
    ADMIN_PHONE,
    CUSTOMER_PHONE
  ]);
  assert.deepEqual(connection.rows.map((row) => row.template_name), [
    "admin_order_created",
    "customer_order_created"
  ]);
  for (const row of connection.rows) {
    assert.match(row.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.match(row.dedupe_key, /^[0-9a-f]{64}$/);
    assert.deepEqual(JSON.parse(row.payload), {
      order_id: ORDER_ID,
      created_at: "2026-01-02T16:04:05.000Z",
      customer_name: "Fallback Customer",
      customer_phone: "98765 43210",
      customer_email: "ada@example.test",
      items: completeOrder().items,
      final_amount: 28,
      payment_method: "online",
      payment_status: "paid",
      address: completeOrder().address
    });
  }
  assert.equal(logs.length, 0);
});

test("customer event requires feature enablement, literal consent, valid phone, and valid template", async (t) => {
  const cases = [
    ["feature disabled", { WHATSAPP_CUSTOMER_CONFIRMATION_ENABLED: "false" }, {}],
    ["consent false", {}, { customer_whatsapp_consent: false }],
    ["string consent", {}, { customer_whatsapp_consent: "true" }],
    ["invalid phone", {}, { customer_phone: "not-a-phone" }],
    ["missing template", { WHATSAPP_CUSTOMER_ORDER_TEMPLATE_NAME: "" }, {}]
  ];

  for (const [name, env, order] of cases) {
    await t.test(name, async () => {
      const connection = new EnqueueConnection();
      const { service } = serviceFixture({ env });
      const result = await service.enqueueForOrder(connection, completeOrder(order));
      assert.deepEqual(result, { adminQueued: true, customerQueued: false });
      assert.deepEqual(connection.rows.map((row) => row.notification_kind), [ADMIN_KIND]);
    });
  }
});

test("online dedupe uses payment ID, COD dedupe uses order ID, and keys separate kind and recipient", () => {
  const common = {
    kind: ADMIN_KIND,
    orderId: ORDER_ID,
    paymentMethod: "online",
    paymentId: "pay_same",
    recipient: ADMIN_PHONE
  };
  const online = createDedupeKey(common);
  assert.equal(online, createDedupeKey({ ...common, orderId: OTHER_ORDER_ID }));
  assert.notEqual(online, createDedupeKey({ ...common, paymentId: "pay_other" }));
  assert.notEqual(online, createDedupeKey({ ...common, kind: CUSTOMER_KIND }));
  assert.notEqual(online, createDedupeKey({ ...common, recipient: CUSTOMER_PHONE }));

  const cod = createDedupeKey({
    ...common,
    paymentMethod: "cod",
    paymentId: "ignored-one"
  });
  assert.equal(cod, createDedupeKey({
    ...common,
    paymentMethod: "cod",
    paymentId: "ignored-two"
  }));
  assert.notEqual(cod, createDedupeKey({
    ...common,
    orderId: OTHER_ORDER_ID,
    paymentMethod: "cod"
  }));
});

test("duplicate keys are ignored and reported as not queued under current INSERT IGNORE behavior", async () => {
  const onlineConnection = new EnqueueConnection();
  const { service: onlineService } = serviceFixture({
    env: { WHATSAPP_CUSTOMER_CONFIRMATION_ENABLED: "false" }
  });
  const firstOnline = await onlineService.enqueueForOrder(
    onlineConnection,
    completeOrder({ customer_whatsapp_consent: false })
  );
  const duplicatePayment = await onlineService.enqueueForOrder(
    onlineConnection,
    completeOrder({
      id: OTHER_ORDER_ID,
      customer_whatsapp_consent: false
    })
  );
  assert.deepEqual(firstOnline, { adminQueued: true, customerQueued: false });
  assert.deepEqual(duplicatePayment, { adminQueued: false, customerQueued: false });
  assert.equal(onlineConnection.rows.length, 1);
  assert.equal(onlineConnection.calls.length, 2);

  const codConnection = new EnqueueConnection();
  const { service: codService } = serviceFixture({
    env: { WHATSAPP_CUSTOMER_CONFIRMATION_ENABLED: "false" }
  });
  const cod = completeOrder({
    payment_method: "cod",
    payment_id: "first-ignored",
    customer_whatsapp_consent: false
  });
  assert.equal((await codService.enqueueForOrder(codConnection, cod)).adminQueued, true);
  assert.equal((await codService.enqueueForOrder(codConnection, {
    ...cod,
    payment_id: "second-ignored"
  })).adminQueued, false);
  assert.equal((await codService.enqueueForOrder(codConnection, {
    ...cod,
    id: OTHER_ORDER_ID
  })).adminQueued, true);
  assert.equal(codConnection.rows.length, 2);
});

test("claim and successful processing write the Meta message ID", async () => {
  const event = pendingEvent();
  const f = serviceFixture({ rows: [event] });

  await f.service.processPending();

  assert.equal(f.whatsapp.calls.length, 1);
  assert.deepEqual(f.whatsapp.calls[0], {
    to: ADMIN_PHONE,
    templateName: "admin_order_created",
    language: "en_US",
    components: buildAdminComponents(JSON.parse(event.payload), BASE_ENV)
  });
  assert.equal(f.db.rows[0].status, "sent");
  assert.equal(f.db.rows[0].meta_message_id, "wamid.meta-accepted");
  assert.equal(f.db.rows[0].last_error_code, null);
  assert.equal(f.db.rows[0].attempt_count, 1);
  assert.equal(f.db.rows[0].claim_token, null);
  assert.equal(f.db.rows[0].sent_at.getTime(), NOW);
  assert.equal(f.logs.length, 0);
});

test("competing processPending calls sharing an outbox do not double-send", async () => {
  let releaseSend;
  let signalStarted;
  const started = new Promise((resolve) => { signalStarted = resolve; });
  const blocked = new Promise((resolve) => { releaseSend = resolve; });
  let sends = 0;
  const whatsapp = validWhatsApp({
    async sendTemplate(request) {
      this.calls.push(request);
      sends += 1;
      signalStarted();
      await blocked;
      return { messageId: "wamid.once" };
    }
  });
  const db = new OutboxDatabase([pendingEvent()]);
  const first = serviceFixture({ db, whatsapp }).service;
  const second = serviceFixture({ db, whatsapp }).service;

  const firstRun = first.processPending();
  await started;
  const secondRun = second.processPending();
  await secondRun;
  assert.equal(sends, 1);
  assert.equal(db.rows[0].status, "processing");

  releaseSend();
  await firstRun;
  assert.equal(sends, 1);
  assert.equal(db.rows[0].status, "sent");
  assert.equal(db.rows[0].attempt_count, 1);
  assert.equal(db.rows[0].meta_message_id, "wamid.once");
});

test("provider rejection becomes failed and timeout becomes unknown, with neither retried", async (t) => {
  const cases = [
    [
      "missing template",
      new WhatsAppError(`${ACCESS_TOKEN} ${ADMIN_PHONE} ${PRIVATE_ADDRESS}`, {
        status: 404,
        code: 132001
      }),
      "failed",
      "132001"
    ],
    [
      "provider rejection",
      new WhatsAppError(`${ACCESS_TOKEN} ${ADMIN_PHONE} ${PRIVATE_ADDRESS}`, {
        status: 400,
        code: 132000
      }),
      "failed",
      "132000"
    ],
    [
      "timeout",
      new WhatsAppError(`${ACCESS_TOKEN} ${ADMIN_PHONE} ${PRIVATE_ADDRESS}`, {
        timedOut: true,
        unknownDelivery: true
      }),
      "unknown",
      "delivery_unknown"
    ]
  ];

  for (const [name, error, expectedStatus, expectedCode] of cases) {
    await t.test(name, async () => {
      const whatsapp = validWhatsApp({
        async sendTemplate(request) {
          this.calls.push(request);
          throw error;
        }
      });
      const f = serviceFixture({ rows: [pendingEvent()], whatsapp });

      await f.service.processPending();
      await f.service.processPending();

      assert.equal(whatsapp.calls.length, 1);
      assert.equal(f.db.rows[0].status, expectedStatus);
      assert.equal(f.db.rows[0].last_error_code, expectedCode);
      assert.equal(f.db.rows[0].meta_message_id, null);
      assert.equal(f.db.rows[0].attempt_count, 1);
      assert.equal(f.db.rows[0].claim_token, null);
      assert.equal(f.logs.length, 1);
      assert.deepEqual(f.logs[0], [
        "WhatsApp order notification failed",
        {
          notificationId: "notification-1",
          status: expectedStatus,
          providerCode: error.code
        }
      ]);

      const visible = JSON.stringify(f.logs);
      const payload = pendingEvent().payload;
      for (const secret of [ACCESS_TOKEN, ADMIN_PHONE, CUSTOMER_PHONE, PRIVATE_ADDRESS, payload]) {
        assert.equal(visible.includes(secret), false, `log leaked ${secret}`);
      }
    });
  }
});

test("stale processing claims become unknown without being sent or retried", async () => {
  const f = serviceFixture({ rows: [pendingEvent({
    status: "processing",
    attempt_count: 1,
    claim_token: "abandoned-claim",
    claimed_at: new Date(NOW - 11 * 60 * 1000)
  })] });

  await f.service.processPending();
  await f.service.processPending();

  assert.equal(f.db.rows[0].status, "unknown");
  assert.equal(f.db.rows[0].last_error_code, "stale_claim");
  assert.equal(f.db.rows[0].attempt_count, 1);
  assert.equal(f.whatsapp.calls.length, 0);
  assert.equal(f.logs.length, 0);
  assert.deepEqual(f.db.calls[0].params, [10]);
});

test("worker database errors report safe diagnostics and allow a later pass to recover", async (t) => {
  for (const [code, errno, expectedCode] of [
    ["ER_NO_SUCH_TABLE", 1146, "ER_NO_SUCH_TABLE"],
    ["ER_BAD_FIELD_ERROR", 1054, "ER_BAD_FIELD_ERROR"],
    ["ECONNREFUSED", -4078, "ECONNREFUSED"],
    [ACCESS_TOKEN, undefined, undefined]
  ]) {
    await t.test(code, async () => {
      const db = new OutboxDatabase([pendingEvent()]);
      const query = db.query.bind(db);
      let fail = true;
      db.query = async (...args) => {
        if (fail) {
          fail = false;
          throw Object.assign(new Error(`${ACCESS_TOKEN} ${PRIVATE_ADDRESS}`), {
            code, errno, sql: pendingEvent().payload
          });
        }
        return query(...args);
      };
      const f = serviceFixture({ db });
      await f.service.processPending();
      assert.equal(f.whatsapp.calls.length, 0);
      assert.equal(f.db.rows[0].status, "pending");
      assert.equal(f.logs[0][0], "WhatsApp notification worker failed");
      assert.equal(f.logs[0][1].code, expectedCode);
      assert.equal(f.logs[0][1].errno, errno);
      if (code.startsWith("ER_")) assert.match(f.logs[0][1].hint, /migrations\/20261112_create_whatsapp_notification_outbox\.sql/);
      const visible = JSON.stringify(f.logs);
      for (const secret of [ACCESS_TOKEN, PRIVATE_ADDRESS, pendingEvent().payload]) {
        assert.equal(visible.includes(secret), false, `log leaked ${secret}`);
      }
      await f.service.processPending();
      assert.equal(f.db.rows[0].status, "sent");
      assert.equal(f.whatsapp.calls.length, 1);
    });
  }
});

test("failed status persistence logs safe database details and does not resend the claim", async () => {
  const db = new OutboxDatabase([pendingEvent()]);
  const query = db.query.bind(db);
  db.query = async (sql, params) => {
    if (sql.includes("SET status = ?")) {
      throw Object.assign(new Error(`${ACCESS_TOKEN} ${PRIVATE_ADDRESS}`), {
        code: "ER_BAD_FIELD_ERROR", errno: 1054, sql
      });
    }
    return query(sql, params);
  };
  const whatsapp = validWhatsApp({ async sendTemplate(request) {
    this.calls.push(request);
    throw new WhatsAppError("template missing", { status: 404, code: 132001 });
  } });
  const f = serviceFixture({ db, whatsapp });
  await f.service.processPending();
  await f.service.processPending();
  assert.equal(whatsapp.calls.length, 1);
  assert.equal(db.rows[0].status, "processing");
  assert.equal(f.logs[0][0], "Failed to update WhatsApp notification status");
  assert.equal(f.logs[0][1].code, "ER_BAD_FIELD_ERROR");
  assert.equal(f.logs[1][1].providerCode, 132001);
  const visible = JSON.stringify(f.logs);
  assert.equal(visible.includes(ACCESS_TOKEN), false);
  assert.equal(visible.includes(PRIVATE_ADDRESS), false);
});

test("missing admin configuration avoids enqueue and worker database processing", async () => {
  const db = {
    calls: [],
    async query(...args) {
      this.calls.push(args);
      throw new Error("database must not be touched");
    }
  };
  const whatsapp = validWhatsApp();
  const { logs, logger } = createLogger();
  const service = createOrderNotificationService({
    db,
    whatsapp,
    env: { ...BASE_ENV, WHATSAPP_ADMIN_PHONE: "" },
    logger,
    now: () => new Date(NOW)
  });
  const connection = new EnqueueConnection();

  assert.equal(service.isConfigured(), false);
  assert.deepEqual(await service.enqueueForOrder(connection, completeOrder()), {
    adminQueued: false,
    customerQueued: false
  });
  await service.processPending();

  assert.equal(connection.calls.length, 0);
  assert.equal(db.calls.length, 0);
  assert.equal(whatsapp.calls.length, 0);
  assert.deepEqual(logs, [[
    "WhatsApp admin order notification is not configured"
  ]]);
  const visible = JSON.stringify(logs);
  assert.equal(visible.includes(ACCESS_TOKEN), false);
  assert.equal(visible.includes(PRIVATE_ADDRESS), false);
});

test("migration enforces unique dedupe and the terminal unknown state", () => {
  const migration = fs.readFileSync(path.join(
    __dirname,
    "..",
    "migrations",
    "20261112_create_whatsapp_notification_outbox.sql"
  ), "utf8");

  assert.match(migration, /UNIQUE KEY uq_whatsapp_notification_dedupe \(dedupe_key\)/);
  assert.match(migration, /status ENUM\('pending', 'processing', 'sent', 'failed', 'unknown'\)/);
  assert.match(migration, /UNIQUE KEY uq_whatsapp_notification_claim \(claim_token\)/);
});

test("checkout statically preserves transaction, response, cleanup, and post-response kick ordering", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
  const start = source.indexOf('app.post("/api/checkout"');
  const end = source.indexOf("app.get(\"/coupons/validate/:code\"", start);
  assert.ok(start >= 0 && end > start, "checkout route was not found");
  const checkout = source.slice(start, end);

  const enqueue = checkout.indexOf("await orderNotifications.enqueueForOrder(connection");
  const commit = checkout.indexOf("await connection.commit()");
  const cleanup = checkout.indexOf("DELETE FROM phone_otps");
  const response = checkout.indexOf("res.json({", commit);
  const kick = checkout.indexOf("orderNotifications.kick()", response);
  assert.ok(enqueue >= 0, "notification enqueue is awaited");
  assert.ok(enqueue < commit, "notification enqueue must be inside the transaction");
  assert.ok(commit < cleanup, "OTP cleanup must happen after commit");
  assert.ok(cleanup < response, "cleanup remains before the success response");
  assert.ok(response < kick, "worker kick must happen after the response");

  assert.match(checkout, /try\s*{\s*await db\.query\(\s*`DELETE FROM phone_otps[\s\S]*?}\s*catch\s*{\s*console\.error\("OTP cleanup failed after committed order",\s*{\s*orderId\s*}\s*\);\s*}/);
  assert.match(checkout, /res\.json\(\{\s*success: true,\s*order_id: orderId,\s*subtotal,\s*tax,\s*shipping,\s*discount,\s*final_amount: finalAmount\s*}\);/);
});
