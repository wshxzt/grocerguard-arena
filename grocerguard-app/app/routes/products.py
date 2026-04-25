from flask import Blueprint, render_template, request, current_app
from sqlalchemy import func

from app.models import db, Product

products = Blueprint('products', __name__)


@products.route('/')
def index():
    category = request.args.get('category', '')
    search = request.args.get('q', '').strip()
    query = Product.query.filter_by(is_available=True)
    if category:
        query = query.filter_by(category=category)
    if search:
        query = query.filter(func.lower(Product.name).like(f'%{search.lower()}%'))
    items = query.order_by(Product.category, Product.name).all()
    categories = (
        db.session.query(Product.category)
        .filter(Product.is_available == True, Product.category != None)
        .distinct()
        .order_by(Product.category)
        .all()
    )
    categories = [c[0] for c in categories if c[0]]
    gcs = current_app.gcs_service
    return render_template('products.html', products=items, categories=categories,
                           selected_category=category, search=search, gcs=gcs)


@products.route('/product/<product_id>')
def detail(product_id):
    product = Product.query.get_or_404(product_id)
    gcs = current_app.gcs_service
    return render_template('product_detail.html', product=product, gcs=gcs)
