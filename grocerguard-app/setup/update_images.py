"""Update product image URLs in the database to GCS-hosted generated images."""
from app import create_app
from app.models import db, Product

BUCKET = 'https://storage.googleapis.com/zhiting-personal-grocerguard-images'

# All products now point to AI-generated images in GCS.
# Atlantic Salmon, Pasta Rigatoni, Canned Black Beans use loremflickr temporarily
# (image generation quota exhausted — will be replaced when quota resets).
IMAGES = {
    'Organic Bananas':        f'{BUCKET}/products/organic_bananas.jpg',
    'Fuji Apples':            f'{BUCKET}/products/fuji_apples.jpg',
    'Baby Spinach':           f'{BUCKET}/products/baby_spinach.jpg',
    'Roma Tomatoes':          f'{BUCKET}/products/roma_tomatoes.jpg',
    'Avocados':               f'{BUCKET}/products/avocados.jpg',
    'Broccoli':               f'{BUCKET}/products/broccoli.jpg',
    'Whole Milk':             f'{BUCKET}/products/whole_milk.jpg',
    'Greek Yogurt':           f'{BUCKET}/products/greek_yogurt.jpg',
    'Large Eggs':             f'{BUCKET}/products/large_eggs.jpg',
    'Sharp Cheddar':          f'{BUCKET}/products/sharp_cheddar.jpg',
    'Sourdough Loaf':         f'{BUCKET}/products/sourdough_loaf.jpg',
    'Whole Wheat Bread':      f'{BUCKET}/products/whole_wheat_bread.jpg',
    'Croissants':             f'{BUCKET}/products/croissants.jpg',
    'Chicken Breast':         f'{BUCKET}/products/chicken_breast.jpg',
    'Atlantic Salmon':        'https://loremflickr.com/400/300/salmon,fish?lock=15',   # TODO: replace
    'Lean Ground Beef':       f'{BUCKET}/products/lean_ground_beef.jpg',
    'Pasta Rigatoni':         'https://loremflickr.com/400/300/pasta?lock=17',          # TODO: replace
    'Olive Oil Extra Virgin': f'{BUCKET}/products/olive_oil.jpg',
    'Canned Black Beans':     'https://loremflickr.com/400/300/beans?lock=19',          # TODO: replace
    'Jasmine Rice':           f'{BUCKET}/products/jasmine_rice.jpg',
}


def run():
    app = create_app()
    with app.app_context():
        updated = 0
        for name, url in IMAGES.items():
            p = Product.query.filter_by(name=name).first()
            if p:
                p.image_path = url
                updated += 1
        db.session.commit()
        print(f'Updated {updated} product images.')


if __name__ == '__main__':
    run()
