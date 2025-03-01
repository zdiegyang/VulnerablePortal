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


# TODO: Patch all vulnerabilities that I can find in the app
# TODO: Ensure proper Logging and Monitoring


app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')  

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB limit

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

# Function to set CSP headers
# Implementation of DOM to prevent XSS and other code execution in the browser
@app.after_request
def set_csp(response):
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


# Route: Home Page
@app.route('/')
def home():
    return render_template('home.html')


# Route: Login (Weak Authentication)
# Added parametized SQL queries, SQL injection is patched now
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
                
        # Secure authentication
        cursor.execute("SELECT password, salt FROM users_secure WHERE username=%s", (username,))
        user_secure = cursor.fetchone()

        if user_secure:
            password_secure, salt = user_secure
            if hash.is_password_same(password, password_secure, salt):
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



# Route: Login Success
@app.route('/login_success')
def login_success():
    if 'user' in session:
        return render_template('login_success.html', username=session['user'])
    return redirect(url_for('login'))


# Route: Signup (Weak Authentication)
# SQL queries are now parametized, and new users' data is now stored securely using hashing and salting
@app.route('/signup', methods=['GET', 'POST'])
def signup():
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


# Route: File Upload updated with sanitation
@app.route('/upload', methods=['GET', 'POST'])
def upload():
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


# Route: Execute Admin Command with a reduced command set that is allowed to avoid excessive exploitation
# Added authentication: only 'admin' can execute cmd 
@app.route('/exec', methods=['POST'])
def execute():
    if 'user' in session and session['user'] == 'admin':
        cmd = request.form.get("cmd")
        
        allowed_commands = ['ls', 'pwd', 'whoami']
        
        if cmd not in allowed_commands:
            return "Command not allowed."
        
        result = subprocess.getoutput(cmd)

        return result
    return redirect(url_for('login'))


# Route: View Employee Details 
# Escaping is implemented to avoid special characters from being executed as code by the browser
# Added authentication: only 'admin' can access this endpoint and access employee data
@app.route('/employee', methods=['GET'])
def employee():
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


# Route: API Endpoint for viewing user data
# Authentication required to access this endpoint --> only admin privileges are allowed
@app.route('/api/data', methods=['GET'])
def api_data():
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
    if 'user' in session and session['user'] == 'admin':
        return render_template('admin.html', username=session['user'])
    return redirect(url_for('login'))


# Route: View Users (Admin Functionality)
@app.route('/view_users')
def view_users():
    if 'user' in session and session['user'] == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users_secure")
        users = cursor.fetchall()
        conn.close()
        return render_template('view_users.html', users=users)
    return redirect(url_for('login'))


# Route: View Employees (Admin Functionality)
@app.route('/view_employees')
def view_employees():
    if 'user' in session and session['user'] == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees")
        employees = cursor.fetchall()
        conn.close()
        return render_template('view_employees.html', employees=employees)
    return redirect(url_for('login'))


# Route: Manage Users and Employees (Admin Functionality)
@app.route('/manage', methods=['GET', 'POST'])
def manage():
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
    if 'user' in session and session['user'] == 'admin':
        files = os.listdir(UPLOAD_FOLDER)
        return render_template('view_files.html', files=files)
    return redirect(url_for('login'))


# Route: Delete File (Admin Functionality)
@app.route('/delete_file', methods=['POST'])
def delete_file():
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
    return send_from_directory(UPLOAD_FOLDER, filename)


# Route: View File
@app.route('/view_file/<filename>')
def view_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# Route: View Files for Users
@app.route('/user_files')
def user_files():
    files = os.listdir(UPLOAD_FOLDER)
    return render_template('user_files.html', files=files)


# Route: Logout
@app.route('/logout')
def logout():
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
