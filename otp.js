
const axios = require("axios");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const { rateLimit, ipKeyGenerator } = require("express-rate-limit");

const {
  WhatsAppError,
  positiveInteger,
  normalizePhone,
  createWhatsAppClient
} = require("./whatsapp");

function createOtpHandlers({
  db,
  http = axios,
  env = process.env,
  now = Date.now,
  logger = console
}) {
  const expiryMinutes = positiveInteger(
    env.OTP_EXPIRY_MINUTES,
    5,
    1440
  );

  const resendCooldown = positiveInteger(
    env.OTP_RESEND_COOLDOWN,
    60
  );

  const defaultCountryCode =
    env.WHATSAPP_DEFAULT_COUNTRY_CODE || "";

  const templateName =
    (env.WHATSAPP_TEMPLATE_NAME || "").trim();

  const language =
    (env.WHATSAPP_TEMPLATE_LANGUAGE || "en_UK").trim();

  const whatsapp = createWhatsAppClient({
    http,
    env,
    logger
  });

  // SEND OTP
  async function sendOtp(req, res) {
    try {
      const cleanPhone = normalizePhone(
        req.body?.phone,
        defaultCountryCode
      );

      if (!cleanPhone) {
        return res.status(400).json({
          message: "A valid phone number with country code is required"
        });
      }

      if (
        !whatsapp.isConfigured() ||
        !whatsapp.isTemplateValid(templateName, language)
      ) {
        logger.error(
          "WhatsApp OTP configuration is missing or invalid"
        );

        return res.status(503).json({
          message: "WhatsApp OTP is not configured"
        });
      }

      // Check resend cooldown
      const [[existing]] = await db.query(
        `SELECT created_at
         FROM phone_otps
         WHERE phone = ?
         ORDER BY created_at DESC
         LIMIT 1`,
        [cleanPhone]
      );

      if (existing) {
        const diff =
          (now() - new Date(existing.created_at).getTime()) / 1000;

        if (diff < resendCooldown) {
          const wait = Math.ceil(resendCooldown - diff);

          res.setHeader("Retry-After", String(wait));

          return res.status(429).json({
            message: `Wait ${wait} seconds before requesting again`
          });
        }
      }

      // Generate secure six-digit OTP
      const otp = crypto.randomInt(100000, 1000000).toString();

      // Hash OTP before database storage
      const hashedOtp = await bcrypt.hash(otp, 10);

      const expiresAt = new Date(
        now() + expiryMinutes * 60 * 1000
      );

      const id = uuidv4();

      // Remove previous OTP
      await db.query(
        "DELETE FROM phone_otps WHERE phone = ?",
        [cleanPhone]
      );

      // Store new OTP
      await db.query(
        `INSERT INTO phone_otps
         (id, phone, otp, expires_at, is_verified)
         VALUES (?, ?, ?, ?, 0)`,
        [id, cleanPhone, hashedOtp, expiresAt]
      );

      // Send OTP through WhatsApp
      try {
        await whatsapp.sendTemplate({
          to: cleanPhone,
          templateName,
          language,
          components: [
            {
              type: "body",
              parameters: [
                {
                  type: "text",
                  text: otp
                }
              ]
            },
            {
              type: "button",
              sub_type: "url",
              index: "0",
              parameters: [
                {
                  type: "text",
                  text: otp
                }
              ]
            }
          ]
        });
      } catch (err) {
        // Delete only this OTP attempt
        try {
          await db.query(
            "DELETE FROM phone_otps WHERE id = ?",
            [id]
          );
        } catch {
          logger.error(
            "Failed to remove an undelivered WhatsApp OTP"
          );
        }

        if (!(err instanceof WhatsAppError)) {
          logger.error("WhatsApp OTP submission failed");
        }

        return res.status(502).json({
          message: "Unable to send WhatsApp OTP. Please try again."
        });
      }

      return res.json({
        success: true,
        message: "OTP submitted to WhatsApp"
      });

    } catch (err) {
      logger.error("Send OTP operation failed");

      return res.status(500).json({
        message: "Server error"
      });
    }
  }

  // VERIFY OTP
  async function verifyOtp(req, res) {
    try {
      const cleanPhone = normalizePhone(
        req.body?.phone,
        defaultCountryCode
      );

      if (!cleanPhone) {
        return res.status(400).json({
          message: "A valid phone number with country code is required"
        });
      }

      const otp = req.body?.otp;

      if (
        typeof otp !== "string" ||
        !/^\d{6}$/.test(otp.trim())
      ) {
        return res.status(400).json({
          message: "A six-digit OTP is required"
        });
      }

      // Fetch latest unverified OTP
      const [[record]] = await db.query(
        `SELECT id, otp, expires_at
         FROM phone_otps
         WHERE phone = ?
         AND is_verified = 0
         ORDER BY created_at DESC
         LIMIT 1`,
        [cleanPhone]
      );

      if (!record) {
        return res.status(400).json({
          message: "Invalid OTP"
        });
      }

      // Check expiration
      const expiresAt = new Date(
        record.expires_at
      ).getTime();

      if (
        !Number.isFinite(expiresAt) ||
        expiresAt <= now()
      ) {
        return res.status(400).json({
          message: "OTP expired"
        });
      }

      // Compare hashed OTP
      const isMatch = await bcrypt.compare(
        otp.trim(),
        record.otp
      );

      if (!isMatch) {
        return res.status(400).json({
          message: "Invalid OTP"
        });
      }

      // Mark OTP as verified
      const [result] = await db.query(
        `UPDATE phone_otps
         SET is_verified = 1
         WHERE id = ?
         AND is_verified = 0
         AND expires_at > ?`,
        [record.id, new Date(now())]
      );

      if (result.affectedRows !== 1) {
        return res.status(400).json({
          message: "Invalid or expired OTP"
        });
      }

      return res.json({
        success: true,
        message: "Phone verified"
      });

    } catch (err) {
      logger.error("Verify OTP operation failed");

      return res.status(500).json({
        message: "Server error"
      });
    }
  }

  return {
    sendOtp,
    verifyOtp
  };
}

// REGISTER OTP ROUTES
function registerOtpRoutes(app, options) {
  const env = options.env || process.env;

  const {
    sendOtp,
    verifyOtp
  } = createOtpHandlers(options);

  const common = {
    windowMs:
      positiveInteger(
        env.OTP_RATE_LIMIT_WINDOW_MINUTES,
        15,
        1440
      ) * 60 * 1000,

    standardHeaders: "draft-7",
    legacyHeaders: false
  };

  // Send OTP rate limit
  const sendLimit = rateLimit({
    ...common,

    limit: positiveInteger(
      env.OTP_SEND_MAX_REQUESTS,
      5
    ),

    message: {
      message: "Too many OTP requests. Please try again later."
    }
  });

  // Verification IP rate limit
  const verifyIpLimit = rateLimit({
    ...common,

    limit: positiveInteger(
      env.OTP_VERIFY_IP_MAX_ATTEMPTS,
      20
    ),

    skipSuccessfulRequests: true,

    message: {
      message: "Too many verification attempts. Please try again later."
    }
  });

  // Verification phone rate limit
  const verifyPhoneLimit = rateLimit({
    ...common,

    limit: positiveInteger(
      env.OTP_VERIFY_MAX_ATTEMPTS,
      5
    ),

    skipSuccessfulRequests: true,

    keyGenerator: (req) =>
      normalizePhone(
        req.body?.phone,
        env.WHATSAPP_DEFAULT_COUNTRY_CODE || ""
      ) || ipKeyGenerator(req.ip),

    message: {
      message: "Too many verification attempts. Please try again later."
    }
  });

  app.post(
    "/api/send-otp",
    sendLimit,
    sendOtp
  );

  app.post(
    "/api/verify-otp",
    verifyIpLimit,
    verifyPhoneLimit,
    verifyOtp
  );
}

module.exports = {
  normalizePhone,
  createOtpHandlers,
  registerOtpRoutes
};
