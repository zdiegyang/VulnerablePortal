import secrets
from flask import Flask, request, render_template, session, redirect, url_for, send_from_directory
from markupsafe import escape 
import os
import subprocess
from database import init_db, get_db_connection, add_user, delete_user, add_employee, delete_employee
import hashing as hash
import sanitizefile
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging 
from datetime import timedelta



app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')  

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB limit

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

logging.basicConfig(level=logging.INFO)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

# 
@app.before_request
def make_session_permanent():
    """Sessions are marked as permanent so that session lifetime is applied. """ 

    session.permanent = True


@app.after_request
def set_csp(response):
    """Function to set CSP headers. This is an implementation of DOM and SOP to prevent XSS and 
    other forms of code execution from being performed."""

    nonce = secrets.token_urlsafe(16)
    csp = {
        "default-src": "'self'",
        "script-src": f"'self' 'nonce-{nonce}'",
        "style-src": "'self'",
        "img-src": "'self'",
        "font-src": "'self'",
        "connect-src": "'self'",
        "frame-src": "'none'",
        "object-src": "'none'", 
        "base-uri": "'none'"
    }
    csp_header = "; ".join([f"{key} {value}" for key, value in csp.items()])
    response.headers["Content-Security-Policy"] = csp_header
    response.set_cookie("nonce", nonce, httponly=True, secure=True, samesite="Strict")
    return response


@app.route('/')
def home():
    """Renders the home page of the website. """
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """Processes login requests from users, and adds the username to the table of active sessions if login is successful.
    This version of the function parametized SQL queries in order to avoid SQL injection, and implements rate limitation 
    to avoid brute-force attacks. """
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        logging.info(f"Login attempt for user: {username}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
                
        # Secure authentication
        cursor.execute("SELECT password, salt FROM users_secure WHERE username=%s", (username,))
        user_secure = cursor.fetchone()

        if user_secure:
            password_secure, salt = user_secure
            if hash.is_password_same(password, password_secure, salt):
                session.clear() # Regenerates session ID
                session['user'] = username
                cursor.execute("INSERT INTO active_sessions (username) VALUES (%s) ON DUPLICATE KEY UPDATE login_time=CURRENT_TIMESTAMP", (username,))
                conn.commit()
                conn.close()
                if username == 'admin':
                    return redirect(url_for('admin'))  
                return redirect(url_for('login_success'))
            else:
                conn.close()
                return "Invalid credentials."
        else:
            conn.close()
            return "Invalid credentials."

    return render_template('login.html')



@app.route('/login_success')
def login_success():
    """Renders the page after a users has successfully logged in. """

    if 'user' in session:
        return render_template('login_success.html', username=session['user'])
    
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Processes signup operation for new users. SQL queries are also parametized here, and we also use hashing and salting for 
    password storage. """

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()

        hashed_password, salt = hash.hash_password(password)
        cursor.execute("INSERT INTO users_secure (username, password, salt) VALUES (%s, %s, %s)", (username, hashed_password, salt))

        conn.commit()
        conn.close()
        return redirect(url_for('login'))  
    return render_template('signup.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():

    """Handles the upload of files with input santitation. Does not accept files outside the allowed extensions nor executable files 
    and performs a lightweight scan to detect these. """

    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file uploaded."
        file = request.files['file']
        file = request.files['file']
        
        if file.filename == '':
            return "No selected file."
        
        if not sanitizefile.allowed_file(file.filename):
            return "File type not allowed."
        
        if file.content_length > app.config["MAX_CONTENT_LENGTH"]:
            return "File is too large."
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)

        file.save(filepath)

        if not sanitizefile.is_safe_scan(filepath):
            return "Potential unsafe file! Upload rejected."
        
        return f"File {file.filename} uploaded!"
    
    return render_template('upload.html')


@app.route('/exec', methods=['POST'])
def execute():
    """Executes Admin Command with a reduced command set in order to avoid excessive explotation. 
    Allowed commands: 'ls', 'pwd', 'whoami'. 
    Only admin can execute these commads via browser. """

    if 'user' in session and session['user'] == 'admin':
        cmd = request.form.get("cmd")
        
        allowed_commands = ['ls', 'pwd', 'whoami']
        
        if cmd not in allowed_commands:
            return "Command not allowed."
        
        result = subprocess.getoutput(cmd)

        return result
    return redirect(url_for('login'))


@app.route('/employee', methods=['GET'])
def employee():

    """Endpoint for viewing employee details. Escaping is implemented to avoid special characters from being executed as code 
    by the browser. 
    Only admin user can access this endpoint (prior authentication is needed here). 
    """

    if 'user' in session and session['user'] == 'admin':
        emp_id = request.args.get("id")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE id=%s", (emp_id,))  
        employee = cursor.fetchone()
        conn.close()
        if employee:
            return render_template('employee.html', name=escape(employee[1]), email=escape(employee[2]))
    return "Employee not found."


@app.route('/api/data', methods=['GET'])
def api_data():

    """API endpoint for viewing user data. Authentication is now required to access this endpoint: only admin is allowed to 
    access this."""

    if 'user'in session and session['user'] == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username FROM users_secure")  
        users = cursor.fetchall()
        conn.close()
        return {"users": users}
    return "Not allowed" 


# Route: Admin Panel
@app.route('/admin')
def admin():
    """Renders the admin panel. """

    if 'user' in session and session['user'] == 'admin':
        return render_template('admin.html', username=session['user'])
    return redirect(url_for('login'))


@app.route('/view_users')
def view_users():

    """Admin Functionality: View user data (now it does not display passwords in plaintext)"""

    if 'user' in session and session['user'] == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users_secure")
        users = cursor.fetchall()
        conn.close()
        return render_template('view_users.html', users=users)
    return redirect(url_for('login'))


@app.route('/view_employees')
def view_employees():
    """Admin Functionality: View employee details"""

    if 'user' in session and session['user'] == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees")
        employees = cursor.fetchall()
        conn.close()
        return render_template('view_employees.html', employees=employees)
    return redirect(url_for('login'))


@app.route('/manage', methods=['GET', 'POST'])
def manage():

    """Admin Functionality: Manages user and employee data. Admin can add/delete users and employees on the database"""

    if 'user' in session and session['user'] == 'admin':
        if request.method == 'POST':
            action = request.form['action']
            if action == 'add_user':
                username = request.form['username']
                password = request.form['password']
                add_user(username, password)
            elif action == 'delete_user':
                username = request.form['username']
                delete_user(username)
            elif action == 'add_employee':
                name = request.form['name']
                email = request.form['email']
                address = request.form['address']
                add_employee(name, email, address)
            elif action == 'delete_employee':
                name = request.form['name']
                delete_employee(name)
            return redirect(url_for('admin'))
        return render_template('manage.html')
    return redirect(url_for('login'))


# Route: View Active Sessions (Admin Functionality)
@app.route('/view_active_sessions')
def view_active_sessions():

    """Admin Functionality: View the current active sessions. """

    if 'user' in session and session['user'] == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username, login_time FROM active_sessions")
        active_sessions = cursor.fetchall()
        conn.close()
        return render_template('view_active_sessions.html', active_sessions=active_sessions)
    return redirect(url_for('login'))


# Route: View Files (Admin Functionality)
@app.route('/view_files')
def view_files():

    """Admin Functionality: View uploaded files by users via the admin panel. """

    if 'user' in session and session['user'] == 'admin':
        files = os.listdir(UPLOAD_FOLDER)
        return render_template('view_files.html', files=files)
    return redirect(url_for('login'))


# Route: Delete File (Admin Functionality)
@app.route('/delete_file', methods=['POST'])
def delete_file():

    """Admin Functionality: Delete uploaded files. """

    if 'user' in session and session['user'] == 'admin':
        filename = request.form['filename']
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        return redirect(url_for('view_files'))
    return redirect(url_for('login'))


# Route: Download File
@app.route('/download_file/<filename>')
def download_file(filename):
    """Downloads a file from the browser. """
    return send_from_directory(UPLOAD_FOLDER, filename)


# Route: View File
@app.route('/view_file/<filename>')
def view_file(filename):
    """Views the file in the browser"""
    return send_from_directory(UPLOAD_FOLDER, filename)


# Route: View Files for Users
@app.route('/user_files')
def user_files():
    """Renders the page to view all the uploaded files. """
    files = os.listdir(UPLOAD_FOLDER)
    return render_template('user_files.html', files=files)


# Route: Logout
@app.route('/logout')
def logout():
    """Logout functionality. Removes the username that has logged out from the table of active sessions"""
    if 'user' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM active_sessions WHERE username=%s", (session['user'],))
        conn.commit()
        conn.close()
    session.pop('user', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
