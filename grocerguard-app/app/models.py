import uuid
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


def _uuid():
    return str(uuid.uuid4())


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    __table_args__ = (
        db.Index('uq_users_username', 'username', unique=True),
        db.Index('uq_users_email', 'email', unique=True),
    )

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(200))
    shipping_address = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    orders = db.relationship('Order', backref='customer', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Product(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=0)
    category = db.Column(db.String(100))
    unit = db.Column(db.String(50), default='each')
    image_path = db.Column(db.String(500))
    is_available = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    order_items = db.relationship('OrderItem', backref='product', lazy=True)

    def get_image_url(self, gcs_service=None):
        if not self.image_path:
            keyword = self.name.split()[0].lower()
            return f'https://loremflickr.com/400/300/{keyword}'
        if self.image_path.startswith('http'):
            return self.image_path
        if gcs_service and gcs_service.is_configured():
            return gcs_service.get_public_url(self.image_path)
        keyword = self.name.split()[0].lower()
        return f'https://loremflickr.com/400/300/{keyword}'

    def __repr__(self):
        return f'<Product {self.name}>'


class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')
    total_price = db.Column(db.Float, nullable=False)
    shipping_address = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    items = db.relationship('OrderItem', backref='order', lazy=True, cascade='all, delete-orphan')

    @property
    def item_count(self):
        return sum(item.quantity for item in self.items)

    def __repr__(self):
        return f'<Order {self.id}>'


class OrderItem(db.Model):
    __tablename__ = 'order_items'

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    order_id = db.Column(db.String(36), db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.String(36), db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)

    @property
    def subtotal(self):
        return self.quantity * self.unit_price

    def __repr__(self):
        return f'<OrderItem order={self.order_id} product={self.product_id}>'
