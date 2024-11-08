from flask import Flask, request, redirect, url_for, render_template, send_from_directory, session, flash
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'xlsx', 'xls'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

users = {
    "admin": generate_password_hash("admin")
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if 'username' in session:
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        file_count = len(files)
        return render_template('index.html', file_count=file_count, files=files)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(url_for('index'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(url_for('index'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File uploaded successfully')
            return redirect(url_for('files'))
        
        flash('File not allowed')
        return redirect(url_for('index'))
    
    return render_template('upload.html')

@app.route('/files')
def files():
    if 'username' not in session:
        return redirect(url_for('login'))
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('files.html', files=files)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' in session and session['username'] == 'admin':
        return render_template('admin.html', users=users.keys(), files=os.listdir(app.config['UPLOAD_FOLDER']))
    return redirect(url_for('login'))

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    if 'username' in session and session['username'] == 'admin':
        new_username = request.form['new_username']
        new_password = request.form['new_password']
        users[new_username] = generate_password_hash(new_password)
        flash('New user added successfully')
        return redirect(url_for('admin'))
    return redirect(url_for('login'))

@app.route('/admin/remove_upload', methods=['POST'])
def remove_upload():
    if 'username' in session and session['username'] == 'admin':
        filename = request.form['filename']
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('File removed successfully')
        return redirect(url_for('admin'))
    return redirect(url_for('login'))

@app.route('/admin/remove_user', methods=['POST'])
def remove_user():
    if 'username' in session and session['username'] == 'admin':
        remove_username = request.form['remove_username']
        if remove_username in users:
            del users[remove_username]
            flash('User removed successfully')
        return redirect(url_for('admin'))
    return redirect(url_for('login'))

@app.route('/admin/uploaded_list')
def uploaded_list():
    if 'username' in session and session['username'] == 'admin':
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        return render_template('files.html', files=files)
    return redirect(url_for('login'))

@app.route('/admin/users_logged_in')
def users_logged_in():
    if 'username' in session and session['username'] == 'admin':
        return render_template('admin.html', users=users.keys())
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(host='0.0.0.0', port=5000, debug=True)
