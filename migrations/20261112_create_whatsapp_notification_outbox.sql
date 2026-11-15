-- Apply this migration before deploying the order-notification code.
-- MySQL 8.0+ / InnoDB.
-- order_id must match orders.id in type, character set, and collation.

CREATE TABLE IF NOT EXISTS whatsapp_notification_outbox (
  id CHAR(36) NOT NULL,
  order_id VARCHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  notification_kind ENUM('admin_order', 'customer_confirmation') NOT NULL,
  recipient VARCHAR(15) NOT NULL,
  template_name VARCHAR(512) NOT NULL,
  template_language VARCHAR(16) NOT NULL,
  dedupe_key CHAR(64) NOT NULL,
  payload JSON NOT NULL,
  status ENUM('pending', 'processing', 'sent', 'failed', 'unknown') NOT NULL DEFAULT 'pending',
  attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
  available_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  claimed_at DATETIME NULL,
  claim_token CHAR(36) NULL,
  meta_message_id VARCHAR(255) NULL,
  last_error_code VARCHAR(64) NULL,
  sent_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_whatsapp_notification_dedupe (dedupe_key),
  UNIQUE KEY uq_whatsapp_notification_claim (claim_token),
  KEY idx_whatsapp_notification_pending (status, available_at, created_at),
  KEY idx_whatsapp_notification_order (order_id),
  CONSTRAINT fk_whatsapp_notification_order
    FOREIGN KEY (order_id) REFERENCES orders(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
