const express = require("express");
const crypto = require("node:crypto");

const WEBHOOK_PATH = "/api/whatsapp/webhook";

function sameToken(actual, expected) {
  if (typeof actual !== "string") return false;
  const received = Buffer.from(actual);
  const configured = Buffer.from(expected);
  return received.length === configured.length &&
    crypto.timingSafeEqual(received, configured);
}

function registerWhatsAppWebhookRoutes(app, {
  env = process.env,
  logger = console
} = {}) {
  const verifyToken = (env.WHATSAPP_VERIFY_TOKEN || "").trim();
  const appSecret = (env.WHATSAPP_APP_SECRET || "").trim();

  app.get(WEBHOOK_PATH, (req, res) => {
    if (!verifyToken) {
      return res.status(503).json({ message: "WhatsApp webhook is not configured" });
    }
    if (req.query["hub.mode"] !== "subscribe" ||
        !sameToken(req.query["hub.verify_token"], verifyToken)) {
      return res.status(403).json({ message: "Webhook verification failed" });
    }
    const challenge = req.query["hub.challenge"];
    if (typeof challenge !== "string" || !/^\d{1,128}$/.test(challenge)) {
      return res.status(400).json({ message: "Invalid webhook challenge" });
    }
    return res.status(200).type("text/plain").send(challenge);
  });

  // Register before the application's JSON parser: Meta signs the raw bytes.
  app.post(WEBHOOK_PATH,
    express.raw({ type: "application/json", limit: "1mb", inflate: false }),
    (req, res) => {
      if (!appSecret) {
        return res.status(503).json({ message: "WhatsApp webhook is not configured" });
      }
      const signature = req.get("x-hub-signature-256");
      if (!Buffer.isBuffer(req.body) ||
          typeof signature !== "string" || !/^sha256=[a-f\d]{64}$/i.test(signature)) {
        return res.status(403).json({ message: "Invalid webhook signature" });
      }
      const expected = crypto.createHmac("sha256", appSecret).update(req.body).digest();
      const received = Buffer.from(signature.slice(7), "hex");
      if (!crypto.timingSafeEqual(received, expected)) {
        return res.status(403).json({ message: "Invalid webhook signature" });
      }

      let event;
      try {
        event = JSON.parse(req.body.toString("utf8"));
      } catch {
        return res.status(400).json({ message: "Invalid webhook payload" });
      }
      if (event?.object !== "whatsapp_business_account" || !Array.isArray(event.entry)) {
        return res.status(400).json({ message: "Invalid webhook payload" });
      }

      // Acknowledge authenticated events and log counts, without message content,
      // recipient numbers, tokens or the complete provider payload.
      let messages = 0;
      let statuses = 0;
      for (const entry of event.entry) {
        if (!Array.isArray(entry?.changes)) continue;
        for (const change of entry.changes) {
          if (change?.field !== "messages") continue;
          if (Array.isArray(change.value?.messages)) messages += change.value.messages.length;
          if (Array.isArray(change.value?.statuses)) statuses += change.value.statuses.length;
        }
      }
      logger.info("WhatsApp webhook received", { messages, statuses });
      return res.sendStatus(200);
    },
    (err, req, res, next) => {
      if (err.type === "entity.too.large") {
        return res.status(413).json({ message: "Webhook payload is too large" });
      }
      if (err.status === 415) {
        return res.status(415).json({ message: "Unsupported webhook encoding" });
      }
      return next(err);
    }
  );
}

module.exports = { WEBHOOK_PATH, registerWhatsAppWebhookRoutes };
