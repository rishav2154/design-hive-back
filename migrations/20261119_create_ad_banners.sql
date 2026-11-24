-- Pop-up advertisement banner system.
-- Apply before deploying the banner routes. MySQL 8.0+ / InnoDB.

CREATE TABLE IF NOT EXISTS ad_banners (
  id CHAR(36) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT NULL,
  image_url VARCHAR(1024) NULL,
  coupon_code VARCHAR(100) NULL,
  cta_text VARCHAR(150) NULL,
  cta_link VARCHAR(1024) NULL,
  bg_color VARCHAR(32) NOT NULL DEFAULT '#1a1a2e',
  text_color VARCHAR(32) NOT NULL DEFAULT '#ffffff',
  accent_color VARCHAR(32) NOT NULL DEFAULT '#e94560',
  priority INT NOT NULL DEFAULT 0,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  starts_at DATETIME NULL,
  ends_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_ad_banners_active (is_active, priority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ad_banner_events (
  id CHAR(36) NOT NULL,
  banner_id CHAR(36) NOT NULL,
  event_type ENUM('view', 'click', 'copy', 'dismiss') NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_ad_banner_events_banner (banner_id, event_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ad_banner_settings (
  id TINYINT NOT NULL,
  is_enabled TINYINT(1) NOT NULL DEFAULT 1,
  permanent_close_on_last TINYINT(1) NOT NULL DEFAULT 0,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO ad_banner_settings (id, is_enabled, permanent_close_on_last)
VALUES (1, 1, 0)
ON DUPLICATE KEY UPDATE id = id;
