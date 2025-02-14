from flask import Flask, request, render_template, session, redirect, url_for, send_from_directory
import os
import subprocess
from database import init_db, get_db_connection, add_user, delete_user, add_employee, delete_employee
import hashing as hash



app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')  

UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

# Route: Home Page
@app.route('/')
def home():
    return render_template('home.html')

# Route: Login (Weak Authentication)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insecure authentication
        cursor.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")  # SQL Injection Vulnerability
        user_insecure = cursor.fetchone()
        
        # Secure authentication
        cursor.execute("SELECT password, salt FROM users_secure WHERE username=%s", (username,))
        user_secure = cursor.fetchone()

        if user_insecure:
            session['user'] = username  # Insecure session management
            cursor.execute("INSERT INTO active_sessions (username) VALUES (%s) ON DUPLICATE KEY UPDATE login_time=CURRENT_TIMESTAMP", (username,))
            conn.commit()
            conn.close()
            if username == 'admin':
                return redirect(url_for('admin')) 
            return redirect(url_for('login_success'))  
        elif user_secure:
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
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))

        hashed_password, salt = hash.hash_password(password)
        cursor.execute("INSERT INTO users_secure (username, password, salt) VALUES (%s, %s, %s)", (username, hashed_password, salt))

        conn.commit()
        conn.close()
        return redirect(url_for('login'))  
    return render_template('signup.html')

# Route: File Upload (Unrestricted File Upload)
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file uploaded."
        file = request.files['file']
        file.save(os.path.join(UPLOAD_FOLDER, file.filename))  
        return f"File {file.filename} uploaded!"
    return render_template('upload.html')

# Route: Execute Admin Command (Command Injection)
@app.route('/exec', methods=['POST'])
def execute():
    cmd = request.form.get("cmd")
    result = subprocess.getoutput(cmd)  # Directly executes input (RCE vulnerability)
    return result

# Route: View Employee Details (IDOR & XSS Vulnerability)
@app.route('/employee', methods=['GET'])
def employee():
    emp_id = request.args.get("id")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM employees WHERE id={emp_id}")  
    employee = cursor.fetchone()
    conn.close()
    if employee:
        return f"<h1>{employee[1]}</h1><p>Email: {employee[2]}</p>"  
    return "Employee not found."

# Route: Insecure API Endpoint (No Authentication)
@app.route('/api/data', methods=['GET'])
def api_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")  
    users = cursor.fetchall()
    conn.close()
    return {"users": users} 

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
        cursor.execute("SELECT * FROM users")
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
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)  
