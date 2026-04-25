"""Download food images from Wikimedia Commons and upload them to GCS,
then update each product's image_path in the database to the GCS object path."""
import io
import requests
from app import create_app
from app.models import db, Product
from app.gcs import GCSService

BUCKET = 'zhiting-personal-grocerguard-images'

# product name → (wikimedia source URL, GCS destination path)
IMAGES = {
    'Fuji Apples': (
        'https://upload.wikimedia.org/wikipedia/commons/thumb/c/c1/Fuji_apple.jpg/400px-Fuji_apple.jpg',
        'products/fuji_apples.jpg',
    ),
    'Whole Milk': (
        'https://upload.wikimedia.org/wikipedia/commons/thumb/f/f1/Kirkland_Milk_Jug.JPG/400px-Kirkland_Milk_Jug.JPG',
        'products/whole_milk.jpg',
    ),
    'Greek Yogurt': (
        'https://upload.wikimedia.org/wikipedia/commons/thumb/5/59/Fresh_greek_yoghurt.jpg/400px-Fresh_greek_yoghurt.jpg',
        'products/greek_yogurt.jpg',
    ),
    'Large Eggs': (
        'https://upload.wikimedia.org/wikipedia/commons/thumb/b/b1/Carton_of_eggs.jpg/400px-Carton_of_eggs.jpg',
        'products/large_eggs.jpg',
    ),
    'Sharp Cheddar': (
        'https://upload.wikimedia.org/wikipedia/commons/thumb/1/18/Somerset-Cheddar.jpg/400px-Somerset-Cheddar.jpg',
        'products/sharp_cheddar.jpg',
    ),
    'Chicken Breast': (
        'https://upload.wikimedia.org/wikipedia/commons/thumb/d/d1/Raw_chicken.jpg/400px-Raw_chicken.jpg',
        'products/chicken_breast.jpg',
    ),
    'Lean Ground Beef': (
        'https://upload.wikimedia.org/wikipedia/commons/thumb/2/2b/Minced_meat.jpg/400px-Minced_meat.jpg',
        'products/lean_ground_beef.jpg',
    ),
    'Olive Oil Extra Virgin': (
        'https://upload.wikimedia.org/wikipedia/commons/thumb/1/13/Bottle_of_olive_oil.jpg/400px-Bottle_of_olive_oil.jpg',
        'products/olive_oil.jpg',
    ),
    'Jasmine Rice': (
        'https://upload.wikimedia.org/wikipedia/commons/thumb/4/4b/Thai_jasmine_rice_uncooked.jpg/400px-Thai_jasmine_rice_uncooked.jpg',
        'products/jasmine_rice.jpg',
    ),
}

HEADERS = {'User-Agent': 'GrocerGuard/1.0 (image migration; contact: admin@grocerguard.com)'}


def run():
    gcs = GCSService(BUCKET)
    app = create_app()
    with app.app_context():
        uploaded = 0
        for name, (src_url, gcs_path) in IMAGES.items():
            print(f'Downloading {name}...', end=' ', flush=True)
            resp = requests.get(src_url, headers=HEADERS, timeout=30)
            resp.raise_for_status()
            content_type = resp.headers.get('Content-Type', 'image/jpeg').split(';')[0]
            gcs.upload_file(io.BytesIO(resp.content), gcs_path, content_type=content_type)
            p = Product.query.filter_by(name=name).first()
            if p:
                p.image_path = gcs_path
                uploaded += 1
                print(f'uploaded → {gcs_path}')
            else:
                print(f'WARNING: product "{name}" not found in DB')
        db.session.commit()
        print(f'\nDone. Uploaded and updated {uploaded} products.')


if __name__ == '__main__':
    run()
