import pymysql
import hashing as hash

# MySQL database connection details
# This type of credential storage might be insecure 
# TODO: Modify db access credentials to not store them in plaintext in the code (Cryptographic Failures and Security Misconfiguration)
db_config = {
    'host': '46.244.8.65',
    'user': 'diego',
    'password': 'password',
    'database': 'computer_security_lab'
}

def get_db_connection():
    """Gets the connection to the remote MySQL database given the credentials and configuration."""
    return pymysql.connect(**db_config)

def init_db():
    """Initializes the database. """

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE,
        password VARCHAR(255)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS employees (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255),
        email VARCHAR(255), 
        address VARCHAR(255)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users_secure (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE,
        password VARCHAR(255),
        salt VARCHAR(255)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS active_sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE,
        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Check if admin user already exists
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    admin_user = cursor.fetchone()
    if not admin_user:
        cursor.execute("""
        INSERT INTO users (username, password) VALUES ('admin', 'password123')
        """)  # Hardcoded password (bad practice)
        admin_hashed_password, salt = hash.hash_password("password123")
        cursor.execute("""
        INSERT INTO users_secure (username, password, salt) VALUES (%s, %s, %s)
        """, ("admin", admin_hashed_password, salt))

    conn.commit()
    conn.close()

def search_user(username): 
    """Searches for the username in the database"""

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users_secure WHERE username=%s", (username,))
    user = cursor.fetchall()

    conn.close()
    return user


def search_employee(employee_name): 
    """Searches for the employee name in the database"""

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM employees WHERE name=%s", (employee_name,))
    user = cursor.fetchall()

    conn.close()
    return user


def add_user(username, password):
    """Inserts a new entry to the existing users. """

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Hash the password and insert into users_secure table (secure)
    hashed_password, salt = hash.hash_password(password)
    cursor.execute("INSERT INTO users_secure (username, password, salt) VALUES (%s, %s, %s)", (username, hashed_password, salt))

    conn.commit()
    conn.close()

def delete_user(username):
    """Deletes a user from the database. """
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM users_secure WHERE username=%s", (username,))

    conn.commit()
    conn.close()

def add_employee(name, email, address):
    """Adds a new entry to the existing employees. """

    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("INSERT INTO employees (name, email, address) VALUES (%s, %s, %s)", (name, email, address))

    conn.commit()
    conn.close()

def delete_employee(employee_name):
    """Deletes an employee from the database. """

    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM employees WHERE name=%s", (employee_name,))

    conn.commit()
    conn.close()

def view_table_db(table): 
    """Returns the data from a table in the database. """

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM %s", (table,))
    data_from_table = cursor.fetchall()

    conn.close()
    return data_from_table



