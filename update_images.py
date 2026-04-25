"""Update product image URLs in the database to food-relevant photos."""
from app import create_app
from app.models import db, Product

# Wikimedia Commons 400px thumbnails — verified exact-match food photos.
# Remaining products keep loremflickr as fallback.
IMAGES = {
    'Organic Bananas':        'https://loremflickr.com/400/300/banana?lock=1',
    'Fuji Apples':            'https://upload.wikimedia.org/wikipedia/commons/thumb/c/c1/Fuji_apple.jpg/400px-Fuji_apple.jpg',
    'Baby Spinach':           'https://loremflickr.com/400/300/spinach?lock=3',
    'Roma Tomatoes':          'https://loremflickr.com/400/300/tomato?lock=4',
    'Avocados':               'https://loremflickr.com/400/300/avocado?lock=5',
    'Broccoli':               'https://loremflickr.com/400/300/broccoli?lock=6',
    'Whole Milk':             'https://upload.wikimedia.org/wikipedia/commons/thumb/f/f1/Kirkland_Milk_Jug.JPG/400px-Kirkland_Milk_Jug.JPG',
    'Greek Yogurt':           'https://upload.wikimedia.org/wikipedia/commons/thumb/5/59/Fresh_greek_yoghurt.jpg/400px-Fresh_greek_yoghurt.jpg',
    'Large Eggs':             'https://upload.wikimedia.org/wikipedia/commons/thumb/b/b1/Carton_of_eggs.jpg/400px-Carton_of_eggs.jpg',
    'Sharp Cheddar':          'https://upload.wikimedia.org/wikipedia/commons/thumb/1/18/Somerset-Cheddar.jpg/400px-Somerset-Cheddar.jpg',
    'Sourdough Loaf':         'https://loremflickr.com/400/300/sourdough,bread?lock=11',
    'Whole Wheat Bread':      'https://loremflickr.com/400/300/bread?lock=12',
    'Croissants':             'https://loremflickr.com/400/300/croissant?lock=13',
    'Chicken Breast':         'https://upload.wikimedia.org/wikipedia/commons/thumb/d/d1/Raw_chicken.jpg/400px-Raw_chicken.jpg',
    'Atlantic Salmon':        'https://loremflickr.com/400/300/salmon,fish?lock=15',
    'Lean Ground Beef':       'https://upload.wikimedia.org/wikipedia/commons/thumb/2/2b/Minced_meat.jpg/400px-Minced_meat.jpg',
    'Pasta Rigatoni':         'https://loremflickr.com/400/300/pasta?lock=17',
    'Olive Oil Extra Virgin': 'https://upload.wikimedia.org/wikipedia/commons/thumb/1/13/Bottle_of_olive_oil.jpg/400px-Bottle_of_olive_oil.jpg',
    'Canned Black Beans':     'https://loremflickr.com/400/300/beans?lock=19',
    'Jasmine Rice':           'https://upload.wikimedia.org/wikipedia/commons/thumb/4/4b/Thai_jasmine_rice_uncooked.jpg/400px-Thai_jasmine_rice_uncooked.jpg',
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
