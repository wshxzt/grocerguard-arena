"""Populate the database with sample grocery products and users."""
from app import create_app
from app.models import db, User, Product

PRODUCTS = [
    # Fruits & Vegetables
    dict(name='Organic Bananas', category='Fruits & Vegetables', price=0.99, stock=150, unit='per lb',
         image_path='https://loremflickr.com/400/300/banana?lock=1',
         description='Sweet, ripe organic bananas. Great for smoothies or a quick snack.'),
    dict(name='Fuji Apples', category='Fruits & Vegetables', price=1.49, stock=120, unit='per lb',
         image_path='https://loremflickr.com/400/300/apple?lock=2',
         description='Crisp, sweet Fuji apples grown in Washington State.'),
    dict(name='Baby Spinach', category='Fruits & Vegetables', price=3.99, stock=60, unit='5 oz bag',
         image_path='https://loremflickr.com/400/300/spinach?lock=3',
         description='Fresh, pre-washed baby spinach. Ready to eat.'),
    dict(name='Roma Tomatoes', category='Fruits & Vegetables', price=2.49, stock=80, unit='per lb',
         image_path='https://loremflickr.com/400/300/tomato?lock=4',
         description='Firm, meaty Roma tomatoes ideal for sauces and salads.'),
    dict(name='Avocados', category='Fruits & Vegetables', price=1.29, stock=100, unit='each',
         image_path='https://loremflickr.com/400/300/avocado?lock=5',
         description='Hass avocados, perfectly ripe and ready to eat.'),
    dict(name='Broccoli', category='Fruits & Vegetables', price=2.29, stock=70, unit='per head',
         image_path='https://loremflickr.com/400/300/broccoli?lock=6',
         description='Large, fresh broccoli crowns packed with vitamins.'),
    # Dairy & Eggs
    dict(name='Whole Milk', category='Dairy & Eggs', price=4.29, stock=90, unit='1 gallon',
         image_path='https://loremflickr.com/400/300/milk?lock=7',
         description='Fresh whole milk from grass-fed cows.'),
    dict(name='Greek Yogurt', category='Dairy & Eggs', price=5.99, stock=55, unit='32 oz',
         image_path='https://loremflickr.com/400/300/yogurt?lock=8',
         description='Plain whole-milk Greek yogurt, thick and creamy.'),
    dict(name='Large Eggs', category='Dairy & Eggs', price=5.49, stock=110, unit='dozen',
         image_path='https://loremflickr.com/400/300/eggs?lock=9',
         description='Free-range large eggs from local farms.'),
    dict(name='Sharp Cheddar', category='Dairy & Eggs', price=6.99, stock=45, unit='16 oz block',
         image_path='https://loremflickr.com/400/300/cheese,cheddar?lock=10',
         description='Aged sharp cheddar with bold, complex flavor.'),
    # Bakery
    dict(name='Sourdough Loaf', category='Bakery', price=7.49, stock=30, unit='per loaf',
         image_path='https://loremflickr.com/400/300/sourdough,bread?lock=11',
         description='Artisan sourdough baked fresh daily with a crispy crust.'),
    dict(name='Whole Wheat Bread', category='Bakery', price=4.99, stock=50, unit='per loaf',
         image_path='https://loremflickr.com/400/300/bread?lock=12',
         description='Nutty, hearty whole wheat bread, sliced.'),
    dict(name='Croissants', category='Bakery', price=3.99, stock=35, unit='4-pack',
         image_path='https://loremflickr.com/400/300/croissant?lock=13',
         description='Buttery, flaky French-style croissants.'),
    # Proteins
    dict(name='Chicken Breast', category='Proteins', price=8.99, stock=60, unit='per lb',
         image_path='https://loremflickr.com/400/300/chicken?lock=14',
         description='Boneless, skinless chicken breast, antibiotic-free.'),
    dict(name='Atlantic Salmon', category='Proteins', price=12.99, stock=30, unit='per lb',
         image_path='https://loremflickr.com/400/300/salmon,fish?lock=15',
         description='Wild-caught Atlantic salmon fillet, rich in omega-3.'),
    dict(name='Lean Ground Beef', category='Proteins', price=7.49, stock=45, unit='per lb',
         image_path='https://loremflickr.com/400/300/beef,meat?lock=16',
         description='90% lean ground beef, locally sourced.'),
    # Pantry
    dict(name='Pasta Rigatoni', category='Pantry', price=2.19, stock=100, unit='16 oz box',
         image_path='https://loremflickr.com/400/300/pasta?lock=17',
         description='Bronze-die cut Italian rigatoni pasta.'),
    dict(name='Olive Oil Extra Virgin', category='Pantry', price=9.99, stock=40, unit='500 ml',
         image_path='https://loremflickr.com/400/300/olive,oil?lock=18',
         description='Cold-pressed extra virgin olive oil from Spain.'),
    dict(name='Canned Black Beans', category='Pantry', price=1.49, stock=120, unit='15 oz can',
         image_path='https://loremflickr.com/400/300/beans?lock=19',
         description='No-salt-added organic black beans.'),
    dict(name='Jasmine Rice', category='Pantry', price=6.99, stock=80, unit='5 lb bag',
         image_path='https://loremflickr.com/400/300/rice?lock=20',
         description='Fragrant Thai jasmine rice, long grain.'),
]

ADMIN_USERS = [
    dict(username='admin', email='admin@grocerguard.com', password='Admin1234!', is_admin=True,
         full_name='Store Manager'),
    dict(username='superadmin', email='super@grocerguard.com', password='Super5678!', is_admin=True,
         full_name='Super Admin'),
]

REGULAR_USERS = [
    dict(username='alice', email='alice@example.com', password='password123',
         full_name='Alice Johnson', shipping_address='123 Maple St, Springfield, IL 62701'),
    dict(username='bob', email='bob@example.com', password='password123',
         full_name='Bob Smith', shipping_address='456 Oak Ave, Shelbyville, IL 62565'),
    dict(username='charlie', email='charlie@example.com', password='password123',
         full_name='Charlie Brown', shipping_address='789 Pine Rd, Capital City, IL 62702'),
]


def seed():
    app = create_app()
    with app.app_context():
        for u_data in ADMIN_USERS + REGULAR_USERS:
            if not User.query.filter_by(username=u_data['username']).first():
                u = User(
                    username=u_data['username'],
                    email=u_data['email'],
                    full_name=u_data.get('full_name'),
                    shipping_address=u_data.get('shipping_address'),
                    is_admin=u_data.get('is_admin', False),
                )
                u.set_password(u_data['password'])
                db.session.add(u)

        for p_data in PRODUCTS:
            if not Product.query.filter_by(name=p_data['name']).first():
                db.session.add(Product(**p_data, is_available=True))

        db.session.commit()
        print(f'Seeded {len(PRODUCTS)} products and {len(ADMIN_USERS) + len(REGULAR_USERS)} users.')


if __name__ == '__main__':
    seed()
