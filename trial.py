from datetime import datetime
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_basicauth import BasicAuth
import logging
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

# Set up logging with INFO level
logging.basicConfig(level=logging.INFO)

# Function to establish a connection to the SQLite database
def db_connection():
    conn = None
    try:
        conn = sqlite3.connect("dbtrial.sqlite")
    except sqlite3.error as e:
        print(e)
    return conn

# Initialize Flask app
app = Flask(__name__)
port_number = 5000

# Configure rate limiting for API endpoints
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Configure basic authentication for the app
basic_auth = BasicAuth(app)

# Check if a user with a given username already exists in the database
def user_exists(username):
    with sqlite3.connect("dbtrial.sqlite") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        return cursor.fetchone() is not None

# Add a new user to the database
def add_user(username, password, rol_id):
    if user_exists(username):
        return jsonify({'error': 'Username already exists'}), 400

    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    with sqlite3.connect("dbtrial.sqlite") as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user (username, password, rol_id) VALUES (?, ?, ?)",
                       (username, password_hash, rol_id))
        user_id = cursor.lastrowid
        conn.commit()

# Get roles associated with a given user
def get_roles_for_user(username):
    with sqlite3.connect("dbtrial.sqlite") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT r.rol_name FROM user AS u "
                       "INNER JOIN rol AS r ON u.rol_id = r.rol_id "
                       "WHERE u.username = ?", (username,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None

# Check if a user has a specific role
def is_user_in_role(username, role):
    roles = get_roles_for_user(username)
    return role in roles

# Get tasks associated with a given user
def get_task_for_user(username):
    with sqlite3.connect("dbtrial.sqlite") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT t.task_name FROM user AS u "
                       "INNER JOIN rol AS r ON u.rol_id = r.rol_id "
                       "INNER JOIN roltask AS rt ON rt.rol_id = r.rol_id "
                       "INNER JOIN task as t on t.task_id = rt.task_id "
                       "WHERE u.username = ?", (username,))
        results = cursor.fetchall()
        if results:
            return results
        return None

# Check if a user has a specific task
def is_user_in_task(username, task):
    tasks = get_task_for_user(username)
    return task in tasks

# Get user credentials (password hash) from the database
def get_user_credentials(username):
    with sqlite3.connect("dbtrial.sqlite") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM user WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None

# Verify user credentials by comparing provided password with stored password hash
def verify_user_credentials(username, password):
    stored_password_hash = get_user_credentials(username)
    if stored_password_hash:
        return check_password_hash(stored_password_hash, password)
    return False

# Add a log entry to the database
def add_log(message):
    with sqlite3.connect("dbtrial.sqlite") as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO log (message) VALUES (?)", (message,))
        conn.commit()

# Registration endpoint
# curl -X POST -H "Content-Type: application/json" -d "{\"username\": \"user3\", \"password\": \"esde1234\", \"rol_id\": \"1\"}" -v http://localhost:5000/register
@app.route('/register', methods=['POST'])
def register_user():
    new_user = request.json
    try:
        add_user(new_user['username'], new_user['password'], new_user['rol_id'])
        success_message = "A new user was registered"
        app.logger.info(success_message)
        add_log(success_message)
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError as e:
        # Handle the case where the username is not unique
        return jsonify({'error': 'Username already exists'}), 400

# Login endpoint
# curl -X POST -H "Content-Type: application/json" -d "{\"username\": \"user3\", \"password\": \"esde1234\"}" -v http://localhost:5000/login
@app.route('/login', methods=['POST'])
def login_user():
    login_data = request.json
    username = login_data.get('username')
    password = login_data.get('password')

    if username and password and verify_user_credentials(username, password):
        app.config['BASIC_AUTH_USERNAME'] = username
        app.config['BASIC_AUTH_PASSWORD'] = password
        success_message = f"The user {username} was logged in successfully"
        app.logger.info(success_message)
        add_log(success_message)
        return jsonify({'message': 'Login successful'})
    else:
        error_message = "Invalid credentials"
        app.logger.error(error_message)
        add_log(error_message)
        return jsonify({'message': 'Invalid credentials'}), 401

# Endpoint to get a list of products
# curl -v http://localhost:5000/products
@app.route('/products')
@limiter.limit("2/minute")
@basic_auth.required
def get_products():
    username = request.authorization.username

    allowed_roles = {'customer', 'admin'}

    if any(is_user_in_role(username, role) for role in allowed_roles):
        conn = db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products")
        products = [
            dict(id=row[0], name=row[1])
            for row in cursor.fetchall()
        ]
        if products is not None:
            message = f"Info: The user {username} get products"
            app.logger.info(message)
            add_log(message)
            return jsonify(products)
    else:
        error_message = f"Warning: Unauthorized access to {username}"
        app.logger.warning(error_message)
        add_log(error_message)
        return jsonify({'message': 'Unauthorized access'}), 403

# Endpoint to get a list of products
# curl -v http://localhost:5000/product/1
@app.route('/product/<int:id>')
@limiter.limit("2/minute")
@basic_auth.required
def get_product(id):
    username = request.authorization.username

    allowed_roles = {'customer', 'admin'}

    if any(is_user_in_role(username, role) for role in allowed_roles):
        conn = db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM products WHERE id = ?", (id,))

        product = cursor.fetchone()

        if product is not None:
            product_dict = dict(id=product[0], name=product[1])
            message = f"Info: The product {product_dict} was get"
            app.logger.info(message)
            add_log(message)
            return jsonify(product_dict)
        else:
            error_message1 = "Error: Product not found"
            app.logger.error(error_message1)
            add_log(error_message1)
            return jsonify({'message': 'Product not found'}), 404
    else:
        error_message2 = f"Warning: Unauthorized access to {username}"
        app.logger.warning(error_message2)
        add_log(error_message2)
        return jsonify({'message': 'Unauthorized access'}), 403

# Endpoint to add a new product
# curl --header "Content-Type: application/json" --request POST --data "{\"name\": \"Product 3\"}" -v http://localhost:5000/product
@app.route('/product', methods=['POST'])
@limiter.limit("2/minute")
@basic_auth.required
def post_product():
    username = request.authorization.username

    if (is_user_in_role(username, 'admin')):
        request_product = request.json
        conn = db_connection()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO products (name) VALUES (?)", (request_product['name'],))
        conn.commit()

        new_id = cursor.lastrowid
        new_product = {
            'id': new_id,
            'name': request_product['name']
        }
        message = f"Info: A product was posted by {username}"
        app.logger.info(message)
        add_log(message)
        return jsonify(new_product), 201
    else:
        error_message = f"Warning: Unauthorized access to {username}"
        app.logger.warning(error_message)
        add_log(error_message)
        return jsonify({'message': 'Unauthorized access'}), 403

# Endpoint to update details of a specific product
# curl --header "Content-Type: application/json" --request PUT --data '{"name": "Updated Product 2"}' -v http://localhost:5000/product/2
@app.route('/product/<int:id>', methods=['PUT'])
@limiter.limit("2/minute")
@basic_auth.required
def put_product(id):
    username = request.authorization.username

    if is_user_in_role(username, 'admin'):
        updated_product = request.json

        conn = db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE products SET name = ? WHERE id = ?", (updated_product['name'], id))
        conn.commit()

        if cursor.rowcount > 0:
            message = f"Info: The product {id} was updated to {updated_product['name']} by {username}"
            app.logger.info(message)
            add_log(message)
            return jsonify({'id': id, 'name': updated_product['name']}), 200
        else:
            error = f"Error: Product {id} not found"
            app.logger.error(error)
            add_log(error)
            return jsonify({'message': f'Product with id {id} not found'}), 404
    else:
        error = f"Warning: Unauthorized access to {username}"
        app.logger.warning("Unauthorized access")
        return jsonify({'message': 'Unauthorized access'}), 403

# Endpoint to delete a specific product
# curl --request DELETE -v http://localhost:5000/product/2
@app.route('/product/<int:id>', methods=['DELETE'])
@limiter.limit("2/minute")
@basic_auth.required
def delete_product(id):
    username = request.authorization.username

    if is_user_in_role(username, 'admin'):
        conn = db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM products WHERE id = ?", (id,))
        product = cursor.fetchone()

        if product:
            cursor.execute("DELETE FROM products WHERE id = ?", (id,))
            conn.commit()

            message = f"Info: he product {id} was deleted by {username}"
            app.logger.info(message)
            add_log(message)
            return jsonify({'message': f'Product with id {id} deleted'}), 200
        else:
            error = f"Error: The product {id} not found by {username}"
            app.logger.error(error)
            add_log(error)
            return jsonify({'message': f'Product with id {id} not found'}), 404
    else:
        error = f"Warning: Unauthorized access to {username}"
        app.logger.warning(error)
        add_log(error)
        return jsonify({'message': 'Unauthorized access'}), 403

# Endpoint to delete a specific product
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=port_number)