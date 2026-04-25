from functools import wraps

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user

from app.models import db, User, Product, Order

admin = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return login_required(decorated)


@admin.route('/')
@admin_required
def dashboard():
    stats = {
        'users': User.query.count(),
        'products': Product.query.count(),
        'orders': Order.query.count(),
        'pending_orders': Order.query.filter_by(status='pending').count(),
    }
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    return render_template('admin/dashboard.html', stats=stats, recent_orders=recent_orders)


@admin.route('/users')
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=all_users)


@admin.route('/orders')
@admin_required
def orders():
    status = request.args.get('status', '')
    query = Order.query
    if status:
        query = query.filter_by(status=status)
    all_orders = query.order_by(Order.created_at.desc()).all()
    return render_template('admin/orders.html', orders=all_orders, status_filter=status)


@admin.route('/orders/<order_id>/status', methods=['POST'])
@admin_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status', '').strip()
    valid_statuses = ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled']
    if new_status in valid_statuses:
        order.status = new_status
        db.session.commit()
        flash(f'Order status updated to {new_status}.', 'success')
    else:
        flash('Invalid status.', 'danger')
    return redirect(url_for('admin.orders'))


@admin.route('/products')
@admin_required
def products():
    gcs = current_app.gcs_service
    all_products = Product.query.order_by(Product.category, Product.name).all()
    return render_template('admin/products.html', products=all_products, gcs=gcs)


@admin.route('/products/new', methods=['GET', 'POST'])
@admin_required
def new_product():
    if request.method == 'POST':
        product = Product(
            name=request.form.get('name', '').strip(),
            description=request.form.get('description', '').strip(),
            price=float(request.form.get('price', 0)),
            stock=int(request.form.get('stock', 0)),
            category=request.form.get('category', '').strip(),
            unit=request.form.get('unit', 'each').strip(),
            is_available='is_available' in request.form,
        )
        _handle_image_upload(product, request)
        db.session.add(product)
        db.session.commit()
        flash('Product created.', 'success')
        return redirect(url_for('admin.products'))
    return render_template('admin/product_form.html', product=None)


@admin.route('/products/<product_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        product.name = request.form.get('name', '').strip()
        product.description = request.form.get('description', '').strip()
        product.price = float(request.form.get('price', 0))
        product.stock = int(request.form.get('stock', 0))
        product.category = request.form.get('category', '').strip()
        product.unit = request.form.get('unit', 'each').strip()
        product.is_available = 'is_available' in request.form
        _handle_image_upload(product, request)
        db.session.commit()
        flash('Product updated.', 'success')
        return redirect(url_for('admin.products'))
    return render_template('admin/product_form.html', product=product)


def _handle_image_upload(product, req):
    from flask import current_app
    import uuid, os
    image_file = req.files.get('image')
    if image_file and image_file.filename:
        gcs = current_app.gcs_service
        if gcs.is_configured():
            ext = os.path.splitext(image_file.filename)[1] or '.jpg'
            path = f'products/{uuid.uuid4()}{ext}'
            gcs.upload_file(image_file, path, content_type=image_file.content_type or 'image/jpeg')
            product.image_path = path
