CREATE TABLE users (
  id STRING(36) NOT NULL,
  username STRING(80) NOT NULL,
  email STRING(120) NOT NULL,
  password_hash STRING(256) NOT NULL,
  full_name STRING(200),
  shipping_address STRING(MAX),
  is_admin BOOL,
  created_at TIMESTAMP
) PRIMARY KEY (id);

CREATE UNIQUE INDEX uq_users_username ON users(username);

CREATE UNIQUE INDEX uq_users_email ON users(email);

CREATE TABLE products (
  id STRING(36) NOT NULL,
  name STRING(200) NOT NULL,
  description STRING(MAX),
  price FLOAT64 NOT NULL,
  stock INT64,
  category STRING(100),
  unit STRING(50),
  image_path STRING(500),
  is_available BOOL,
  created_at TIMESTAMP
) PRIMARY KEY (id);

CREATE TABLE orders (
  id STRING(36) NOT NULL,
  user_id STRING(36) NOT NULL,
  status STRING(50),
  total_price FLOAT64 NOT NULL,
  shipping_address STRING(MAX) NOT NULL,
  notes STRING(MAX),
  created_at TIMESTAMP,
  updated_at TIMESTAMP
) PRIMARY KEY (id);

CREATE TABLE order_items (
  id STRING(36) NOT NULL,
  order_id STRING(36) NOT NULL,
  product_id STRING(36) NOT NULL,
  quantity INT64 NOT NULL,
  unit_price FLOAT64 NOT NULL
) PRIMARY KEY (id);
