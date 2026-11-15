const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const {
  WhatsAppError,
  positiveInteger,
  normalizePhone,
  createWhatsAppClient
} = require("./whatsapp");

const ADMIN_KIND = "admin_order";
const CUSTOMER_KIND = "customer_confirmation";

function enabled(value) {
  return String(value || "").trim().toLowerCase() === "true";
}

function workerErrorDetails(err) {
  const details = {};
  // Never log raw database messages or SQL: they can contain order data.
  if (typeof err?.code === "string" &&
      /^(?:ER_[A-Z0-9_]{1,64}|ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN)$/.test(err.code)) {
    details.code = err.code;
  }
  if (Number.isSafeInteger(err?.errno)) details.errno = err.errno;
  if (details.code === "ER_NO_SUCH_TABLE") {
    details.hint = "Apply migrations/20261112_create_whatsapp_notification_outbox.sql to the configured database before starting the worker.";
  } else if (details.code === "ER_BAD_FIELD_ERROR") {
    details.hint = "Check the outbox schema against migrations/20261112_create_whatsapp_notification_outbox.sql.";
  }
  return details;
}

function cleanText(value, fallback = "Not provided") {
  if (value === null || value === undefined) return fallback;
  const text = String(value).replace(/\s+/g, " ").trim();
  return text || fallback;
}

function parseAddress(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  if (typeof value !== "string" || !value.trim()) return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed : {};
  } catch {
    return {};
  }
}

function formatAddress(value) {
  const address = parseAddress(value);
  return [
    address.address_line1,
    address.address_line2,
    address.city,
    address.state,
    address.pincode
  ]
    .map((part) => cleanText(part, ""))
    .filter(Boolean)
    .join(", ") || "Not provided";
}

function formatMoney(value, currency = "INR") {
  const number = Number(value);
  const amount = Number.isFinite(number) ? number.toFixed(2) : "0.00";
  return `${currency} ${amount}`;
}

function formatItems(items, currency = "INR") {
  if (!Array.isArray(items) || !items.length) return "No items";
  return items.map((item) => {
    const name = cleanText(item.product_name || item.name, "Product");
    const quantity = Number.isFinite(Number(item.quantity))
      ? Number(item.quantity) : 0;
    return `${name} x ${quantity} @ ${formatMoney(item.price, currency)}`;
  }).join("; ");
}

function formatOrderDate(value, timeZone = "UTC") {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) return "Not provided";
  try {
    return new Intl.DateTimeFormat("en-GB", {
      timeZone,
      dateStyle: "medium",
      timeStyle: "short",
      hour12: true
    }).format(date);
  } catch {
    return date.toISOString();
  }
}

function textParameter(text) {
  return { type: "text", text: cleanText(text) };
}

function buildAdminComponents(payload, env = process.env) {
  const address = parseAddress(payload.address);
  const currency = (env.WHATSAPP_ORDER_CURRENCY || "INR").trim() || "INR";
  const timeZone = (env.WHATSAPP_ORDER_TIMEZONE || "UTC").trim() || "UTC";
  return [{
    type: "body",
    parameters: [
      textParameter(payload.order_id),
      textParameter(formatOrderDate(payload.created_at, timeZone)),
      textParameter(address.full_name || payload.customer_name),
      textParameter(address.phone || payload.customer_phone),
      textParameter(payload.customer_email),
      textParameter(formatItems(payload.items, currency)),
      textParameter(formatMoney(payload.final_amount, currency)),
      textParameter(`${cleanText(payload.payment_method)} / ${cleanText(payload.payment_status)}`),
      textParameter(formatAddress(address))
    ]
  }];
}

function buildCustomerComponents(payload, env = process.env) {
  const currency = (env.WHATSAPP_ORDER_CURRENCY || "INR").trim() || "INR";
  return [{
    type: "body",
    parameters: [
      textParameter(payload.order_id),
      textParameter(formatItems(payload.items, currency)),
      textParameter(formatMoney(payload.final_amount, currency)),
      textParameter(`${cleanText(payload.payment_method)} / ${cleanText(payload.payment_status)}`),
      textParameter(formatAddress(payload.address))
    ]
  }];
}

function createDedupeKey({ kind, orderId, paymentMethod, paymentId, recipient }) {
  const orderKey = paymentMethod === "online" && paymentId
    ? `payment:${paymentId}`
    : `order:${orderId}`;
  return crypto
    .createHash("sha256")
    .update(`${kind}|${orderKey}|${recipient}`)
    .digest("hex");
}

function createOrderNotificationService({
  db,
  whatsapp = createWhatsAppClient(),
  env = process.env,
  logger = console,
  now = () => new Date()
}) {
  const defaultCountryCode = env.WHATSAPP_DEFAULT_COUNTRY_CODE || "";
  const adminPhone = normalizePhone(env.WHATSAPP_ADMIN_PHONE || "", defaultCountryCode);
  const adminTemplate = (env.WHATSAPP_ADMIN_ORDER_TEMPLATE_NAME || "").trim();
  const adminLanguage = (env.WHATSAPP_ADMIN_ORDER_TEMPLATE_LANGUAGE || "en_US").trim();
  const customerEnabled = enabled(env.WHATSAPP_CUSTOMER_CONFIRMATION_ENABLED);
  const customerTemplate = (env.WHATSAPP_CUSTOMER_ORDER_TEMPLATE_NAME || "").trim();
  const customerLanguage = (env.WHATSAPP_CUSTOMER_ORDER_TEMPLATE_LANGUAGE || "en_US").trim();
  const intervalMs = positiveInteger(env.WHATSAPP_NOTIFICATION_POLL_INTERVAL_MS, 15000, 3600000);
  const claimTimeoutMinutes = positiveInteger(env.WHATSAPP_NOTIFICATION_CLAIM_TIMEOUT_MINUTES, 10, 1440);
  const batchSize = positiveInteger(env.WHATSAPP_NOTIFICATION_BATCH_SIZE, 10, 100);
  let timer = null;
  let processing = false;

  function adminConfigured() {
    return Boolean(
      adminPhone &&
      whatsapp.isConfigured() &&
      whatsapp.isTemplateValid(adminTemplate, adminLanguage)
    );
  }

  function customerConfigured() {
    return Boolean(
      customerEnabled &&
      whatsapp.isConfigured() &&
      whatsapp.isTemplateValid(customerTemplate, customerLanguage)
    );
  }

  async function enqueueForOrder(connection, order) {
    if (!adminConfigured()) {
      logger.error("WhatsApp admin order notification is not configured");
      return { adminQueued: false, customerQueued: false };
    }

    const payload = {
      order_id: order.id,
      created_at: order.created_at || now().toISOString(),
      customer_name: order.customer_name,
      customer_phone: order.customer_phone,
      customer_email: order.customer_email,
      items: order.items,
      final_amount: order.final_amount,
      payment_method: order.payment_method,
      payment_status: order.payment_status,
      address: parseAddress(order.address)
    };

    const events = [{
      id: uuidv4(),
      kind: ADMIN_KIND,
      recipient: adminPhone,
      templateName: adminTemplate,
      language: adminLanguage
    }];

    const customerPhone = normalizePhone(order.customer_phone || "", defaultCountryCode);
    if (customerConfigured() && order.customer_whatsapp_consent === true && customerPhone) {
      events.push({
        id: uuidv4(),
        kind: CUSTOMER_KIND,
        recipient: customerPhone,
        templateName: customerTemplate,
        language: customerLanguage
      });
    }

    let adminQueued = false;
    let customerQueued = false;
    for (const event of events) {
      const dedupeKey = createDedupeKey({
        kind: event.kind,
        orderId: order.id,
        paymentMethod: order.payment_method,
        paymentId: order.payment_id,
        recipient: event.recipient
      });
      const [result] = await connection.query(
        `INSERT IGNORE INTO whatsapp_notification_outbox
         (id, order_id, notification_kind, recipient, template_name,
          template_language, dedupe_key, payload, status, available_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())`,
        [
          event.id,
          order.id,
          event.kind,
          event.recipient,
          event.templateName,
          event.language,
          dedupeKey,
          JSON.stringify(payload)
        ]
      );
      if (event.kind === ADMIN_KIND) adminQueued = result.affectedRows === 1;
      if (event.kind === CUSTOMER_KIND) customerQueued = result.affectedRows === 1;
    }

    return { adminQueued, customerQueued };
  }

  async function markStaleClaimsUnknown() {
    await db.query(
      `UPDATE whatsapp_notification_outbox
       SET status = 'unknown',
           last_error_code = 'stale_claim',
           updated_at = NOW()
       WHERE status = 'processing'
       AND claimed_at < DATE_SUB(NOW(), INTERVAL ? MINUTE)`,
      [claimTimeoutMinutes]
    );
  }

  async function claimNext() {
    const claimToken = uuidv4();
    const [result] = await db.query(
      `UPDATE whatsapp_notification_outbox
       SET status = 'processing',
           claim_token = ?,
           claimed_at = NOW(),
           attempt_count = attempt_count + 1,
           updated_at = NOW()
       WHERE status = 'pending'
       AND available_at <= NOW()
       ORDER BY created_at
       LIMIT 1`,
      [claimToken]
    );
    if (result.affectedRows !== 1) return null;

    const [[event]] = await db.query(
      `SELECT id, order_id, notification_kind, recipient,
              template_name, template_language, payload
       FROM whatsapp_notification_outbox
       WHERE claim_token = ? AND status = 'processing'
       LIMIT 1`,
      [claimToken]
    );
    return event || null;
  }

  async function complete(event, status, values = {}) {
    await db.query(
      `UPDATE whatsapp_notification_outbox
       SET status = ?,
           meta_message_id = ?,
           last_error_code = ?,
           sent_at = CASE WHEN ? = 'sent' THEN NOW() ELSE sent_at END,
           claim_token = NULL,
           updated_at = NOW()
       WHERE id = ? AND status = 'processing'`,
      [status, values.messageId || null, values.errorCode || null, status, event.id]
    );
  }

  async function processEvent(event) {
    let result;
    try {
      const payload = parseAddress(event.payload);
      const components = event.notification_kind === ADMIN_KIND
        ? buildAdminComponents(payload, env)
        : buildCustomerComponents(payload, env);
      result = await whatsapp.sendTemplate({
        to: event.recipient,
        templateName: event.template_name,
        language: event.template_language,
        components
      });
    } catch (err) {
      const unknown = err instanceof WhatsAppError && err.unknownDelivery;
      const code = err instanceof WhatsAppError && err.code !== undefined
        ? String(err.code)
        : unknown ? "delivery_unknown" : "send_failed";
      try {
        await complete(event, unknown ? "unknown" : "failed", { errorCode: code });
      } catch (updateError) {
        logger.error("Failed to update WhatsApp notification status", {
          notificationId: event.id,
          ...workerErrorDetails(updateError)
        });
      }
      logger.error("WhatsApp order notification failed", {
        notificationId: event.id,
        status: unknown ? "unknown" : "failed",
        providerCode: err instanceof WhatsAppError ? err.code : undefined
      });
      return;
    }

    try {
      await complete(event, "sent", { messageId: result.messageId });
    } catch (err) {
      // Leave the claim in processing. The stale-claim pass will mark it
      // unknown instead of risking a duplicate after Meta accepted it.
      logger.error("Failed to record accepted WhatsApp notification", {
        notificationId: event.id,
        ...workerErrorDetails(err)
      });
    }
  }

  async function processPending() {
    if (processing || !adminConfigured()) return;
    processing = true;
    try {
      await markStaleClaimsUnknown();
      for (let index = 0; index < batchSize; index += 1) {
        const event = await claimNext();
        if (!event) break;
        await processEvent(event);
      }
    } catch (err) {
      logger.error("WhatsApp notification worker failed", workerErrorDetails(err));
    } finally {
      processing = false;
    }
  }

  function kick() {
    setImmediate(() => {
      processPending().catch((err) => {
        logger.error("WhatsApp notification worker failed", workerErrorDetails(err));
      });
    });
  }

  function start() {
    if (timer) return;
    kick();
    timer = setInterval(kick, intervalMs);
    timer.unref?.();
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  return {
    enqueueForOrder,
    processPending,
    kick,
    start,
    stop,
    isConfigured: adminConfigured
  };
}

module.exports = {
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
};
