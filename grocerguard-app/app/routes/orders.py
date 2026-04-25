from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_required, current_user

from app.models import db, Product, Order, OrderItem, _uuid

orders = Blueprint('orders', __name__)


def get_cart():
    return session.get('cart', {})


def cart_count():
    return sum(get_cart().values())


@orders.route('/cart')
@login_required
def cart():
    cart_data = get_cart()
    items = []
    total = 0.0
    gcs = current_app.gcs_service
    for product_id, qty in cart_data.items():
        product = Product.query.get(product_id)
        if product:
            subtotal = product.price * qty
            total += subtotal
            items.append({'product': product, 'quantity': qty, 'subtotal': subtotal})
    return render_template('cart.html', items=items, total=total, gcs=gcs)


@orders.route('/cart/add/<product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    cart = get_cart()
    qty = int(request.form.get('quantity', 1))
    cart[product_id] = cart.get(product_id, 0) + qty
    session['cart'] = cart
    flash(f'Added {product.name} to cart.', 'success')
    return redirect(request.referrer or url_for('products.index'))


@orders.route('/cart/remove/<product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    cart = get_cart()
    cart.pop(product_id, None)
    session['cart'] = cart
    return redirect(url_for('orders.cart'))


@orders.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_data = get_cart()
    if not cart_data:
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('products.index'))

    if request.method == 'POST':
        address = request.form.get('shipping_address', '').strip()
        notes = request.form.get('notes', '').strip()
        if not address:
            flash('Please provide a shipping address.', 'danger')
            return redirect(url_for('orders.checkout'))

        total = 0.0
        order_items = []
        for product_id, qty in cart_data.items():
            product = Product.query.get(product_id)
            if product:
                total += product.price * qty
                order_items.append(OrderItem(
                    product_id=product.id,
                    quantity=qty,
                    unit_price=product.price,
                ))

        order = Order(
            id=_uuid(),
            user_id=current_user.id,
            status='pending',
            total_price=total,
            shipping_address=address,
            notes=notes,
        )
        db.session.add(order)
        for item in order_items:
            item.order_id = order.id
            db.session.add(item)
        db.session.commit()
        session.pop('cart', None)
        flash(f'Order placed successfully!', 'success')
        return redirect(url_for('orders.order_detail', order_id=order.id))

    items = []
    total = 0.0
    gcs = current_app.gcs_service
    for product_id, qty in cart_data.items():
        product = Product.query.get(product_id)
        if product:
            subtotal = product.price * qty
            total += subtotal
            items.append({'product': product, 'quantity': qty, 'subtotal': subtotal})
    default_address = current_user.shipping_address or ''
    return render_template('checkout.html', items=items, total=total,
                           default_address=default_address, gcs=gcs)


@orders.route('/orders')
@login_required
def order_history():
    user_orders = Order.query.filter_by(user_id=current_user.id)\
        .order_by(Order.created_at.desc()).all()
    return render_template('orders.html', orders=user_orders)


@orders.route('/orders/<order_id>')
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('orders.order_history'))
    gcs = current_app.gcs_service
    return render_template('order_detail.html', order=order, gcs=gcs)
