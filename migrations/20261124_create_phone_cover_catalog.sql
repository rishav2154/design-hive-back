-- Unified phone-cover catalog used by /shop, /customize-phone-cover and Admin.
-- Apply before deploying the matching API changes. MySQL 8.0+ / InnoDB.

ALTER TABLE phone_brands
  ADD COLUMN IF NOT EXISTS slug VARCHAR(191) NULL,
  ADD COLUMN IF NOT EXISTS description TEXT NULL,
  ADD COLUMN IF NOT EXISTS logo_url VARCHAR(1024) NULL,
  ADD COLUMN IF NOT EXISTS is_active TINYINT(1) NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS sort_order INT NOT NULL DEFAULT 0;

ALTER TABLE phone_models
  ADD COLUMN IF NOT EXISTS slug VARCHAR(191) NULL,
  ADD COLUMN IF NOT EXISTS image_url VARCHAR(1024) NULL,
  ADD COLUMN IF NOT EXISTS release_year SMALLINT NULL,
  ADD COLUMN IF NOT EXISTS is_active TINYINT(1) NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS sort_order INT NOT NULL DEFAULT 0;

ALTER TABLE cover_types
  ADD COLUMN IF NOT EXISTS slug VARCHAR(191) NULL,
  ADD COLUMN IF NOT EXISTS image_url VARCHAR(1024) NULL,
  ADD COLUMN IF NOT EXISTS is_active TINYINT(1) NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS sort_order INT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS phone_cover_products (
  product_id VARCHAR(36) NOT NULL,
  cover_type_id VARCHAR(36) NULL,
  preview_image_url VARCHAR(1024) NULL,
  requires_image TINYINT(1) NOT NULL DEFAULT 1,
  is_featured TINYINT(1) NOT NULL DEFAULT 0,
  sort_order INT NOT NULL DEFAULT 0,
  customizer_config JSON NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (product_id),
  KEY idx_phone_cover_products_type (cover_type_id),
  KEY idx_phone_cover_products_sort (is_featured, sort_order)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS phone_cover_product_models (
  id CHAR(36) NOT NULL,
  product_id VARCHAR(36) NOT NULL,
  model_id VARCHAR(36) NOT NULL,
  sku VARCHAR(191) NULL,
  price_override DECIMAL(10,2) NULL,
  stock_override INT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_phone_cover_product_model (product_id, model_id),
  KEY idx_phone_cover_product_models_model (model_id, is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS phone_cover_page_settings (
  id TINYINT NOT NULL,
  hero_badge VARCHAR(191) NOT NULL DEFAULT 'Phone Cover Studio',
  hero_title VARCHAR(255) NOT NULL DEFAULT 'Design Your Phone Cover',
  hero_description TEXT NULL,
  instructions_title VARCHAR(191) NOT NULL DEFAULT 'Special Instructions',
  instructions_text TEXT NULL,
  max_upload_mb INT NOT NULL DEFAULT 10,
  min_image_width INT NOT NULL DEFAULT 1200,
  min_image_height INT NOT NULL DEFAULT 1600,
  is_enabled TINYINT(1) NOT NULL DEFAULT 1,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO phone_cover_page_settings (
  id,
  hero_description,
  instructions_text
) VALUES (
  1,
  'Choose a product, phone model and cover type, then upload your design.',
  'Upload a high-resolution image and keep important details away from the edges.'
) ON DUPLICATE KEY UPDATE id = VALUES(id);

