"""Set product image_path columns to repo-bundled static files.

Use this on a fresh clone (or anywhere you don't have a GCS bucket
configured) so the storefront renders with the JPGs that ship with the
repository under app/static/products/. For the production deployment we
use update_images.py instead, which points image_path at GCS URLs."""
from app import create_app
from app.models import db, Product

IMAGES = {
    'Organic Bananas':        'products/organic_bananas.jpg',
    'Fuji Apples':            'products/fuji_apples.jpg',
    'Baby Spinach':           'products/baby_spinach.jpg',
    'Roma Tomatoes':          'products/roma_tomatoes.jpg',
    'Avocados':               'products/avocados.jpg',
    'Broccoli':               'products/broccoli.jpg',
    'Whole Milk':             'products/whole_milk.jpg',
    'Greek Yogurt':           'products/greek_yogurt.jpg',
    'Large Eggs':             'products/large_eggs.jpg',
    'Sharp Cheddar':          'products/sharp_cheddar.jpg',
    'Sourdough Loaf':         'products/sourdough_loaf.jpg',
    'Whole Wheat Bread':      'products/whole_wheat_bread.jpg',
    'Croissants':             'products/croissants.jpg',
    'Chicken Breast':         'products/chicken_breast.jpg',
    'Atlantic Salmon':        'products/atlantic_salmon.jpg',
    'Lean Ground Beef':       'products/lean_ground_beef.jpg',
    'Pasta Rigatoni':         'products/pasta_rigatoni.jpg',
    'Olive Oil Extra Virgin': 'products/olive_oil.jpg',
    'Canned Black Beans':     'products/canned_black_beans.jpg',
    'Jasmine Rice':           'products/jasmine_rice.jpg',
}


def run():
    app = create_app()
    with app.app_context():
        updated = 0
        for name, path in IMAGES.items():
            p = Product.query.filter_by(name=name).first()
            if p:
                p.image_path = path
                updated += 1
        db.session.commit()
        print(f'Updated {updated} product image_path values to bundled static files.')


if __name__ == '__main__':
    run()
