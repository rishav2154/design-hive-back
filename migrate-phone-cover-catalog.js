const mysql = require('mysql2/promise');
require('dotenv').config();

const columns = {
  phone_brands: [
    ['slug', 'VARCHAR(191) NULL'],
    ['description', 'TEXT NULL'],
    ['logo_url', 'VARCHAR(1024) NULL'],
    ['is_active', 'TINYINT(1) NOT NULL DEFAULT 1'],
    ['sort_order', 'INT NOT NULL DEFAULT 0'],
  ],
  phone_models: [
    ['slug', 'VARCHAR(191) NULL'],
    ['image_url', 'VARCHAR(1024) NULL'],
    ['release_year', 'SMALLINT NULL'],
    ['is_active', 'TINYINT(1) NOT NULL DEFAULT 1'],
    ['sort_order', 'INT NOT NULL DEFAULT 0'],
  ],
  cover_types: [
    ['slug', 'VARCHAR(191) NULL'],
    ['image_url', 'VARCHAR(1024) NULL'],
    ['is_active', 'TINYINT(1) NOT NULL DEFAULT 1'],
    ['sort_order', 'INT NOT NULL DEFAULT 0'],
  ],
};

const createStatements = [
  `CREATE TABLE IF NOT EXISTS phone_cover_products (
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
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
  `CREATE TABLE IF NOT EXISTS phone_cover_product_models (
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
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
  `CREATE TABLE IF NOT EXISTS phone_cover_page_settings (
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
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
];

const alignReferenceColumn = async (
  connection,
  targetTable,
  targetColumn,
  sourceTable,
  sourceColumn,
  nullable,
) => {
  const [[source]] = await connection.execute(
    `SELECT COLUMN_TYPE, CHARACTER_SET_NAME, COLLATION_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?
     LIMIT 1`,
    [sourceTable, sourceColumn],
  );
  if (!source) throw new Error(`Missing reference column ${sourceTable}.${sourceColumn}`);

  const columnType = /^(?:var)?char\(\d+\)$/i.test(source.COLUMN_TYPE)
    ? source.COLUMN_TYPE
    : 'VARCHAR(36)';
  const charset = /^[a-z0-9_]+$/i.test(source.CHARACTER_SET_NAME || '')
    ? source.CHARACTER_SET_NAME
    : 'utf8mb4';
  const collation = /^[a-z0-9_]+$/i.test(source.COLLATION_NAME || '')
    ? source.COLLATION_NAME
    : 'utf8mb4_0900_ai_ci';

  await connection.query(
    `ALTER TABLE \`${targetTable}\`
     MODIFY COLUMN \`${targetColumn}\` ${columnType}
     CHARACTER SET ${charset} COLLATE ${collation} ${nullable ? 'NULL' : 'NOT NULL'}`,
  );
};

const main = async () => {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });

  try {
    for (const [table, tableColumns] of Object.entries(columns)) {
      const [existingRows] = await connection.execute(
        `SELECT COLUMN_NAME
         FROM INFORMATION_SCHEMA.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`,
        [table],
      );
      if (existingRows.length === 0) {
        throw new Error(`Required legacy table ${table} does not exist`);
      }

      const existing = new Set(existingRows.map((row) => row.COLUMN_NAME));
      for (const [name, definition] of tableColumns) {
        if (!existing.has(name)) {
          await connection.query(`ALTER TABLE \`${table}\` ADD COLUMN \`${name}\` ${definition}`);
        }
      }
    }

    for (const statement of createStatements) {
      await connection.query(statement);
    }

    await alignReferenceColumn(connection, 'phone_cover_products', 'product_id', 'products', 'id', false);
    await alignReferenceColumn(connection, 'phone_cover_products', 'cover_type_id', 'cover_types', 'id', true);
    await alignReferenceColumn(connection, 'phone_cover_product_models', 'product_id', 'products', 'id', false);
    await alignReferenceColumn(connection, 'phone_cover_product_models', 'model_id', 'phone_models', 'id', false);

    await connection.execute(
      `INSERT INTO phone_cover_page_settings
       (id, hero_description, instructions_text)
       VALUES (1, ?, ?)
       ON DUPLICATE KEY UPDATE id = VALUES(id)`,
      [
        'Choose a product, phone model and cover type, then upload your design.',
        'Upload a high-resolution image and keep important details away from the edges.',
      ],
    );

    console.log('Phone-cover catalog migration completed.');
  } finally {
    await connection.end();
  }
};

main().catch((error) => {
  console.error('Phone-cover catalog migration failed:', error.message);
  process.exitCode = 1;
});

