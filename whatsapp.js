const axios = require("axios");

class WhatsAppError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "WhatsAppError";
    this.status = details.status;
    this.code = details.code;
    this.timedOut = Boolean(details.timedOut);
    this.unknownDelivery = Boolean(details.unknownDelivery);
    this.reason = details.reason;
    this.hint = details.hint;
  }
}

function positiveInteger(value, fallback, maximum = 2147483647) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 && number <= maximum
    ? number
    : fallback;
}

function normalizePhone(phone, defaultCountryCode = "") {
  if (typeof phone !== "string") return null;

  const input = phone.trim();
  if (input.length > 32 || !/^\+?[\d ()-]+$/.test(input)) return null;

  const international = input.startsWith("+");
  let digits = input.replace(/[ ()-]/g, "").replace(/^\+/, "");

  // Bare ten-digit numbers use an explicitly configured country code.
  if (!international && digits.length === 10) {
    const countryCode = String(defaultCountryCode).trim();
    if (!/^[1-9]\d{0,2}$/.test(countryCode)) return null;
    digits = countryCode + digits;
  }

  return /^[1-9]\d{7,14}$/.test(digits) ? digits : null;
}

function getWhatsAppConfig(env = process.env) {
  return {
    accessToken: (env.WHATSAPP_ACCESS_TOKEN || "").trim(),
    phoneNumberId: (env.WHATSAPP_PHONE_NUMBER_ID || "").trim(),
    apiVersion: (env.WHATSAPP_API_VERSION || "").trim(),
    timeout: positiveInteger(env.WHATSAPP_REQUEST_TIMEOUT_MS, 10000, 60000)
  };
}

function isWhatsAppConfigured(config) {
  return Boolean(
    config.accessToken &&
    /^[1-9]\d+$/.test(config.phoneNumberId) &&
    /^v\d+\.\d+$/.test(config.apiVersion)
  );
}

function isTemplateName(value) {
  return typeof value === "string" && /^[a-z0-9_]+$/.test(value);
}

function isTemplateLanguage(value) {
  return typeof value === "string" && /^[a-z]{2,3}(?:_[A-Z]{2})?$/.test(value);
}

function extractWhatsAppError(err) {
  const timedOut = err?.code === "ECONNABORTED" || err?.code === "ETIMEDOUT";
  const unknownDelivery = timedOut || !err?.response;
  const details = {
    status: typeof err?.response?.status === "number"
      ? err.response.status : undefined,
    code: typeof err?.response?.data?.error?.code === "number"
      ? err.response.data.error.code : undefined,
    timedOut
  };
  Object.defineProperty(details, "unknownDelivery", {
    value: unknownDelivery,
    enumerable: false
  });
  return details;
}

function createWhatsAppClient({
  http = axios,
  env = process.env,
  logger = console
} = {}) {
  const config = getWhatsAppConfig(env);

  async function sendTemplate({
    to,
    templateName,
    language = "en_US",
    components = []
  }) {
    const phone = normalizePhone(to, env.WHATSAPP_DEFAULT_COUNTRY_CODE || "");
    if (!isWhatsAppConfigured(config)) {
      throw new WhatsAppError("WhatsApp Cloud API is not configured");
    }
    if (!phone || !isTemplateName(templateName) ||
        !isTemplateLanguage(language) || !Array.isArray(components)) {
      throw new WhatsAppError("Invalid WhatsApp template request");
    }

    try {
      const response = await http.post(
        `https://graph.facebook.com/${config.apiVersion}/${config.phoneNumberId}/messages`,
        {
          messaging_product: "whatsapp",
          recipient_type: "individual",
          to: phone,
          type: "template",
          template: {
            name: templateName,
            language: { code: language },
            components
          }
        },
        {
          headers: {
            Authorization: `Bearer ${config.accessToken}`,
            "Content-Type": "application/json"
          },
          timeout: config.timeout,
          maxRedirects: 0
        }
      );

      const messageId = response?.data?.messages?.[0]?.id;
      if (!(response?.status >= 200 && response.status < 300) ||
          typeof messageId !== "string" || !messageId.trim()) {
        throw new WhatsAppError("WhatsApp did not accept the template message", {
          status: response?.status
        });
      }

      return { messageId: messageId.trim() };
    } catch (err) {
      if (err instanceof WhatsAppError) throw err;

      const details = extractWhatsAppError(err);
      if (details.code === 132001) {
        details.reason = "template_not_found";
        details.templateName = templateName;
        details.language = language;
        details.hint = "Use the exact approved template name and language from the sending number's WhatsApp Business Account.";
      }
      logger.error("WhatsApp Cloud API request failed", details);
      throw new WhatsAppError("WhatsApp Cloud API request failed", details);
    }
  }

  return {
    sendTemplate,
    isConfigured: () => isWhatsAppConfigured(config),
    isTemplateValid: (templateName, language = "en_US") =>
      isTemplateName(templateName) && isTemplateLanguage(language)
  };
}

module.exports = {
  WhatsAppError,
  positiveInteger,
  normalizePhone,
  getWhatsAppConfig,
  isWhatsAppConfigured,
  createWhatsAppClient
};
