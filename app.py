from pymongo import MongoClient
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify, Blueprint, g, abort
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from passlib.hash import scrypt  
from flask_session import Session
from flask_login import current_user


import os
import pytz
import secrets
import hashlib
import locale
import bcrypt
import jwt
import logging 

# Set up logging
logging.basicConfig(level=logging.DEBUG)


# Blueprint digunakan untuk mengatur rute-rute 
# yang terkait dengan halaman-halaman 
# yang terdapat dalam folder views. 
# Setiap rute akan merender template HTML 
# yang sesuai dengan struktur folder yang Anda berikan.
# Blueprint for views
views_bp = Blueprint('views', __name__, template_folder='Templates/views')
 
 

app = Flask(__name__) 

app.secret_key = secrets.token_hex(16)
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Flask-Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'appname_'
app.config['SESSION_COOKIE_NAME'] = 'your_session_cookie_name'

Session(app)


app.secret_key = secrets.token_hex(16)
app.config["TEMPLATES_AUTO_RELOAD"] = True 
app.config["UPLOAD_FOLDER_PENGHUNI"] = 'static/upload/ktp/'
app.config["UPLOAD_FOLDER_TRANSAKSI"] = 'static/upload/transaksi/'
app.config["UPLOAD_FOLDER_KONTRAKAN"] = 'static/upload/kontrakan/'
app.config["UPLOAD_FOLDER_KELUHAN"] = 'static/upload/keluhan/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
 
# Koneksi ke MongoDB
MONGODB_CONNECTION_STRING = "mongodb+srv://tegarsultanrpl:sparta1234@cluster0.jfl6tmu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGODB_CONNECTION_STRING)
db = client.dbkontrakan
users_collection = db['users']

# JWT configuration
SECRET_KEY = app.secret_key
TOKEN_KEY = 'mytoken'


#  ------------------------ START LANDINGPAGE ------------------------ 
# Route untuk halaman utama
@app.route('/')
def landingpage():
    # Ambil seluruh data kontrakan dari MongoDB
    kontrakan_list = db.kontrakan.find()
    return render_template('landing_page.html', kontrakan_list=kontrakan_list)

#  ------------------------ END LANDINGPAGE ------------------------ 



#  ------------------------ START LOGIN ------------------------ 
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logging.debug("User ID not found in session")
            return redirect(url_for('login'))
        logging.debug(f"User ID found in session: {session['user_id']}")
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def wrapper(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                return "Access denied: No user id in session", 403
            
            user = users_collection.find_one({'_id': ObjectId(user_id)})
            if not user:
                return "Access denied: User not found", 403
            
            if user.get('role') != role:
                return "Access denied: Incorrect role", 403
            
            return f(*args, **kwargs)
        return wrapped_function
    return wrapper

# Hashing functions
def generate_password_hash(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password_hash(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


# Add before_request to set current_user
@app.before_request
def load_current_user():
    user_id = session.get('user_id')
    if user_id:
        g.current_user = users_collection.find_one({'_id': ObjectId(user_id)})
    else:
        g.current_user = None

# Add context processor to make current_user available in templates
@app.context_processor
def inject_user():
    return dict(current_user=g.current_user)



# Routes
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('pass')
        logging.debug(f"Login attempt for email: {email}")

        user = users_collection.find_one({'email': email})

        if user:
            logging.debug(f"User found in database: {user['email']}")
            if check_password_hash(password, user['password']):
                payload = {
                    "id": user['email'],
                    "exp": datetime.utcnow() + timedelta(days=1)
                }
                token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                user_role = user.get('role')
                logging.debug(f"User role: {user_role}")

                response = jsonify({"result": "success"})
                response.set_cookie(TOKEN_KEY, token)
                session['user_id'] = str(user['_id'])  # Store user id in session
                logging.debug(f"Session set for user ID: {session['user_id']}")

                if user_role == 'admin':
                    response = redirect(url_for('homepage_admin'))
                elif user_role == 'penghuni':
                    response = redirect(url_for('views.homepage'))
                else:
                    return jsonify({"result": "fail", "msg": "Invalid role"})
                
                response.set_cookie(TOKEN_KEY, token)
                return response
            else:
                logging.debug("Password check failed")
        else:
            logging.debug("User not found in database")

        return jsonify({"result": "fail", "msg": "Invalid email or password"})

    msg = request.args.get("msg")
    return render_template('views/login/login.html', msg=msg)

@app.route("/logout")
def logout():
    response = redirect(url_for('login'))
    response.delete_cookie(TOKEN_KEY)
    session.pop('user_id', None)  # Clear the user id from session
    return response

@app.route("/user/<email>", methods=['GET'])
def user(email):
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        status = email == payload.get('id')
        user_info = db.users.find_one({"email": email}, {"_id": False})
        return render_template("user.html", user_info=user_info, status=status)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))

 
#  ------------------------ END LOGIN ------------------------ 

 
#  ------------------------ START BAGIAN ADMIN  ------------------------ 
#  ------------------------ START HOMEPAGE ------------------------ 

# Define your routes 
@app.route('/admin/homepage')
@login_required
@role_required('admin')
def homepage_admin():
    penghuni_count = db.penghuni.count_documents({})
    kontrakan_count = db.kontrakan.count_documents({})
    keluhan_count = db.keluhan.count_documents({})

    transaksi_total = db.transaksi.aggregate([
        {
            "$group": {
                "_id": None,
                "total": {"$sum": "$total_harga"}
            }
        }
    ])

    transaksi_total = next(transaksi_total)['total'] if transaksi_total else 0

    jakarta_tz = pytz.timezone('Asia/Jakarta')
    now = datetime.now(jakarta_tz)
    current_date = now.strftime('%A, %d %B %Y')
    current_time = now.strftime('%H:%M')

    locale.setlocale(locale.LC_ALL, 'id_ID')

    transaksi_total_str = locale.currency(transaksi_total, grouping=True)

    
    pipeline = [
        {
            '$lookup': {
                'from': 'users',
                'localField': 'penghuni_id',
                'foreignField': '_id',
                'as': 'user_data'
            }
        },
        {
            '$lookup': {
                'from': 'penghuni',
                'localField': 'penghuni_id',
                'foreignField': '_id',
                'as': 'penghuni_data'
            }
        },
        {
            '$addFields': {
                'nama_penghuni': {
                    '$ifNull': [
                        { '$arrayElemAt': ['$user_data.nama', 0] },
                        { '$arrayElemAt': ['$penghuni_data.nama', 0] }
                    ]
                }
            }
        },
        {
            '$lookup': {
                'from': 'kontrakan',
                'localField': 'kontrakan_id',
                'foreignField': '_id',
                'as': 'kontrakan'
            }
        },
        {
            '$unwind': '$kontrakan'
        },
        {
            '$project': {
                '_id': 1,
                'keluhan_penghuni': 1,
                'tgl_keluhan': 1,
                'gambar_keluhan': 1,
                'status': 1,
                'nama_penghuni': 1,
                'nama_kontrakan': '$kontrakan.nama_kontrakan'
            }
        }
    ]

    keluhan_list = list(db.keluhan.aggregate(pipeline))

    # Print results for debugging
    for keluhan in keluhan_list:
        print(keluhan)
    
    return render_template('views/admin/index.html', 
                        current_date=current_date, 
                        current_time=current_time,
                        data_keluhan=keluhan_list,
                        penghuni_count=penghuni_count, 
                        kontrakan_count=kontrakan_count,
                        keluhan_count=keluhan_count, 
                        transaksi_total=transaksi_total_str, 
                        )

#  ------------------------ END HOMEPAGE ------------------------ 
 


#  ------------------------ START PENGHUNI ------------------------ 

# Route for Penghuni page
@views_bp.route('/admin/penghuni')
@login_required
@role_required('admin')
def penghuni():
    # Ambil data penghuni dari database MongoDB
    data_penghuni = db.penghuni.find()
    return render_template('views/admin/penghuni/index.html', data_penghuni=data_penghuni)

# Code untuk route tambah_penghuni
@views_bp.route('/admin/penghuni/tambah_penghuni', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def tambah_penghuni():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        nama = request.form['nama']
        umur = request.form['umur']
        jenisKelamin = request.form['jenisKelamin']
        status = request.form['status']
        poto_ktp = request.files['poto_ktp']
        
        if poto_ktp and allowed_file(poto_ktp.filename):
            today = datetime.now()
            my_time = today.strftime('%Y-%m-%d-%H-%M-%S')
            extention = poto_ktp.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f'poto_ktp_{my_time}.{extention}')
            namaGambar = os.path.join(app.config["UPLOAD_FOLDER_PENGHUNI"], filename)
            poto_ktp.save(namaGambar)
        else:
            flash('File gambar tidak valid!', 'error')
            return redirect(request.url)
        
        # Hash the password using bcrypt
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert data ke collection penghuni
        doc_penghuni = {
            'email': email,
            'password': pw_hash.decode('utf-8'),  # Decode to store as string
            'nama': nama,
            'umur': umur,
            'jenisKelamin': jenisKelamin,
            'status': status,
            'poto_ktp': namaGambar
        }
        db.penghuni.insert_one(doc_penghuni)

        # Insert data ke collection users
        doc_user = {
            'nama': nama,
            'email': email,
            'password': pw_hash.decode('utf-8'),  # Decode to store as string
            'role': 'penghuni'
        }
        db.users.insert_one(doc_user)

        return redirect(url_for('views.penghuni'))

    return render_template('views/admin/penghuni/tambah_penghuni.html')

# Route for edit_penghuni page
@views_bp.route('/admin/penghuni/edit_penghuni/<penghuni_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_penghuni(penghuni_id):
    if request.method == 'GET':
        penghuni = db.penghuni.find_one({"_id": ObjectId(penghuni_id)})
        return render_template('views/admin/penghuni/edit_penghuni.html', penghuni=penghuni)
    elif request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        nama = request.form['nama']
        jenisKelamin = request.form['jenisKelamin']
        status = request.form['status']
        poto_ktp = request.files['poto_ktp']
        
        update_data = {
            'email': email,
            'nama': nama,
            'jenisKelamin': jenisKelamin,
            'status': status,
        }

        if password:
            pw_hash = generate_password_hash(password)
            update_data['password'] = pw_hash
        
        if poto_ktp and allowed_file(poto_ktp.filename):
            today = datetime.now()
            my_time = today.strftime('%Y-%m-%d-%H-%M-%S')
            extention = poto_ktp.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f'poto_ktp_{my_time}.{extention}')
            namaGambar = os.path.join(app.config["UPLOAD_FOLDER_PENGHUNI"], filename)
            poto_ktp.save(namaGambar)
            update_data['poto_ktp'] = namaGambar
        
        # Update data di collection penghuni
        db.penghuni.update_one({'_id': ObjectId(penghuni_id)}, {"$set": update_data})
        
        # Update data di collection users
        user = db.users.find_one({"email": email})
        if user:
            update_user_data = {
                'email': email,
                'nama': nama,
            }
            if password:
                update_user_data['password'] = pw_hash

            db.users.update_one({'_id': user['_id']}, {"$set": update_user_data})
        else:
            flash(f'Pengguna dengan email {email} tidak ditemukan', 'error')

        flash('Penghuni dan pengguna terkait berhasil diperbarui', 'success')
        return redirect(url_for('views.penghuni'))


#  Route for detail penghuni
@views_bp.route('/admin/penghuni/detail_penghuni/<penghuni_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def detail_penghuni(penghuni_id):
    id = ObjectId(penghuni_id)
    penghuni = db.penghuni.find_one({'_id': id})
    if penghuni:
        if request.method == 'POST':
            # Handle POST request if needed
            pass
        return render_template('views/admin/penghuni/detail_penghuni.html', penghuni=penghuni)
    else:
        return "Penghuni tidak ditemukan", 404

# Route for hapus_penghuni
@login_required
@role_required('admin')
@views_bp.route('/admin/penghuni/hapus_penghuni/<penghuni_id>', methods=['POST'])
def hapus_penghuni(penghuni_id):
    try:
        # Dapatkan informasi penghuni untuk menghapus pengguna terkait
        penghuni = db.penghuni.find_one({"_id": ObjectId(penghuni_id)})

        if not penghuni:
            flash('Penghuni tidak ditemukan', 'error')
            return redirect(url_for('views.penghuni'))

        # Hapus data penghuni
        db.penghuni.delete_one({"_id": ObjectId(penghuni_id)})
        
        # Hapus data pengguna yang terkait berdasarkan email atau identifier lainnya
        db.users.delete_one({"email": penghuni['email']})

        flash('Penghuni dan pengguna terkait berhasil dihapus', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('views.penghuni'))

#  ------------------------ END PENGHUNI ------------------------ 



#  ------------------------ START KONTRAKAN ------------------------ 
# routes index kontrakan
@views_bp.route('/admin/kontrakan')
@login_required
@role_required('admin')
def kontrakan():
    # Read - Menampilkan daftar kontrakan
    kontrakan = list(db.kontrakan.find({}))
    return render_template('views/admin/kontrakan/index.html', kontrakan=kontrakan)

# routes tambah kontrakan
@views_bp.route('/admin/kontrakan/tambah_kontrakan', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def tambah_kontrakan():
    if request.method == 'POST':
        # Mengambil data dari form
        nama_kontrakan = request.form['nama_kontrakan']
        harga = request.form['harga']
        status = request.form['status_kontrakan']  # Memperbaiki nama field
        alamat = request.form['alamat']
        kapasitas = request.form['kapasitas']  # Menambahkan kapasitas
        gambar = request.files['image']
        
        # Logika untuk menyimpan gambar (jika ada)
        if gambar.filename != '':
            if allowed_file(gambar.filename):
                today = datetime.now()
                my_time = today.strftime('%Y-%m-%d-%H-%M-%S')
                extention = gambar.filename.split('.')[-1]
                namaGambar = f'kontrakan_{my_time}.{extention}'
                # Pastikan direktori upload ada dan buat jika belum ada
                upload_folder = app.config["UPLOAD_FOLDER_KONTRAKAN"]
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)
                # Simpan file ke direktori yang ditentukan
                gambar.save(os.path.join(upload_folder, namaGambar))
            else:
                # Jika file tidak diizinkan, tampilkan pesan error
                flash('File gambar tidak valid!', 'error')
                return redirect(request.url)
        else: 
            namaGambar = None
        
        # Membuat dokumen untuk disimpan di database
        doc = {
            'nama_kontrakan': nama_kontrakan,
            'harga': harga,
            'status': status,
            'alamat': alamat,
            'kapasitas': kapasitas,  # Menambahkan kapasitas
            'gambar': namaGambar
        }
        
        # Menyimpan data ke database
        db.kontrakan.insert_one(doc)
        
        # Redirect ke halaman utama setelah berhasil menambahkan kontrakan
        return redirect(url_for('views.kontrakan'))
    
    # Render halaman tambah kontrakan jika metode adalah GET
    return render_template('views/admin/kontrakan/tambah_kontrakan.html')

# routes edit kontrakan 
@views_bp.route('/admin/kontrakan/edit_kontrakan/<kontrakan_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_kontrakan(kontrakan_id): 
    if request.method == 'POST':
        # Update - Mengedit kontrakan yang ada
        nama_kontrakan = request.form['nama_kontrakan']
        harga = request.form['harga']
        status = request.form['status']
        alamat = request.form['alamat']
        kapasitas = request.form['kapasitas']
        gambar = request.files['image']
        
        # Pastikan semua data wajib terisi
        if not (nama_kontrakan and harga and status and alamat and kapasitas):
            flash('Semua data wajib diisi', 'error')
            return redirect(request.url)
        
        doc = {
            'nama_kontrakan': nama_kontrakan,
            'harga': harga,
            'status': status,
            'alamat': alamat,
            'kapasitas': kapasitas,
        }
        
        if gambar.filename != '':
            if allowed_file(gambar.filename):
                today = datetime.now()
                my_time = today.strftime('%Y-%m-%d-%H-%M-%S')
                extension = gambar.filename.split('.')[-1]
                namaGambar = f'kontrakan_{my_time}.{extension}'
                upload_folder = app.config["UPLOAD_FOLDER_KONTRAKAN"]
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)
                gambar.save(os.path.join(upload_folder, namaGambar))
                doc['gambar'] = namaGambar
            else:
                flash('File gambar tidak valid!', 'error')
                return redirect(request.url)
        
        db.kontrakan.update_one({'_id': ObjectId(kontrakan_id)}, {'$set': doc})
        flash('Data Kontrakan Berhasil Diupdate!', 'success')
        return redirect(url_for('views.kontrakan'))
    
    data = db.kontrakan.find_one({'_id': ObjectId(kontrakan_id)})
    if not data:
        return "Kontrakan tidak ditemukan", 404
    return render_template('views/admin/kontrakan/edit_kontrakan.html', data=data)

@views_bp.route('/admin/kontrakan/detail_kontrakan/<kontrakan_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def detail_kontrakan(kontrakan_id):
    if request.method == 'POST':
        # Handle POST request if needed
        pass
    # Read - Menampilkan detail kontrakan
    data = db.kontrakan.find_one({'_id': ObjectId(kontrakan_id)})
    if not data:
        return "Kontrakan tidak ditemukan", 404
    return render_template('views/admin/kontrakan/detail_kontrakan.html', data=data)

# routes hapus kontrakan
@views_bp.route('/admin/kontrakan/hapus_kontrakan/<kontrakan_id>', methods=['POST'])
@login_required
@role_required('admin')
def hapus_kontrakan(kontrakan_id):
   
    # Delete - Menghapus kontrakan
    result = db.kontrakan.delete_one({'_id': ObjectId(kontrakan_id)})
    if result.deleted_count == 1:
        return redirect(url_for('views.kontrakan'))
    else:
        return "Kontrakan tidak ditemukan atau tidak dapat dihapus", 404

#  ------------------------ END KONTRAKAN ------------------------ 


#  ------------------------ START TRANSAKSI ------------------------ 
# Route for Transaksi page
@views_bp.route('/admin/transaksi')
@login_required
@role_required('admin')
def transaksi():
    pipeline = [
        {
            '$lookup': {
                'from': 'users',
                'localField': 'penghuni_id',
                'foreignField': '_id',
                'as': 'user_data'
            }
        },
        {
            '$lookup': {
                'from': 'penghuni',
                'localField': 'penghuni_id',
                'foreignField': '_id',
                'as': 'penghuni_data'
            }
        },
        {
            '$addFields': {
                'nama_penghuni': {
                    '$ifNull': [
                        { '$arrayElemAt': ['$user_data.nama', 0] },
                        { '$arrayElemAt': ['$penghuni_data.nama', 0] }
                    ]
                }
            }
        },
        {
            '$lookup': {
                'from': 'kontrakan',
                'localField': 'kontrakan_id',
                'foreignField': '_id',
                'as': 'kontrakan'
            }
        },
        {
            '$unwind': '$kontrakan'
        },
        {
            '$project': {
                '_id': 1,
                'bukti_pembayaran': 1,
                'status': 1,
                'nama_penghuni': 1, 
                'nama_kontrakan': '$kontrakan.nama_kontrakan'
            }
        }
    ]

    data_transaksi = list(db.transaksi.aggregate(pipeline))

    # Print results for debugging
    for transaksi in data_transaksi:
        print(transaksi)

    return render_template('views/admin/transaksi/index.html', data_transaksi=data_transaksi)



# Route for tambah_transaksi page
@views_bp.route('/admin/transaksi/tambah_transaksi', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def tambah_transaksi():
    if request.method == 'POST':
        penghuni_id = request.form['penghuni']
        tgl_pembayaran = request.form['tgl_pembayaran']
        kontrakan_id = request.form['kontrakan']
        harga_perbulan = int(request.form['harga_perbulan'])
        jumlah_sewa = int(request.form['jumlah_sewa'])
        total_harga = int(request.form['total_harga'])
        uang_bayar = int(request.form['uang_bayar'])
        kembalian = int(request.form['kembalian'])
        status = request.form['status']
        bukti_pembayaran = request.files['bukti_pembayaran']

        if bukti_pembayaran and allowed_file(bukti_pembayaran.filename):
            today = datetime.now()
            my_time = today.strftime('%Y-%m-%d-%H-%M-%S')
            extention = bukti_pembayaran.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f'bukti_pembayaran_{my_time}.{extention}')
            namaGambar = os.path.join(app.config["UPLOAD_FOLDER_TRANSAKSI"], filename)
            bukti_pembayaran.save(namaGambar)
        else:
            namaGambar = None

        doc = {
            'penghuni_id': ObjectId(penghuni_id),
            'tgl_pembayaran': tgl_pembayaran,
            'kontrakan_id': ObjectId(kontrakan_id),
            'harga_perbulan': harga_perbulan,
            'jumlah_sewa': jumlah_sewa,
            'total_harga': total_harga,
            'uang_bayar': uang_bayar,
            'kembalian': kembalian,
            'status': status,
            'bukti_pembayaran': namaGambar
        }

        db.transaksi.insert_one(doc)
        return redirect(url_for('views.transaksi'))

    user = db.users.find()
    kontrakan = db.kontrakan.find()
    return render_template('views/admin/transaksi/tambah_transaksi.html', user=user, kontrakan=kontrakan)


# Route for detail_transaksi page
@views_bp.route('/admin/transaksi/detail_transaksi/<transaksi_id>') 
@login_required
@role_required('admin')  # Sesuaikan dengan role yang sesuai
def detail_transaksi(transaksi_id):
    try:
        pipeline = [
            {
                '$match': {
                    '_id': ObjectId(transaksi_id)
                }
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'user_data'
                }
            },
            {
                '$lookup': {
                    'from': 'penghuni',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'penghuni_data'
                }
            },
            {
                '$addFields': {
                    'nama_penghuni': {
                        '$ifNull': [
                            { '$arrayElemAt': ['$user_data.nama', 0] },
                            { '$arrayElemAt': ['$penghuni_data.nama', 0] }
                        ]
                    }
                }
            },
            {
                '$lookup': {
                    'from': 'kontrakan',
                    'localField': 'kontrakan_id',
                    'foreignField': '_id',
                    'as': 'kontrakan'
                }
            },
            {
                '$unwind': '$kontrakan'
            },
            {
                '$project': {
                    '_id': 1,
                    'bukti_pembayaran': 1,
                    'status': 1,
                    'nama_penghuni': 1, 
                    'nama_kontrakan': '$kontrakan.nama_kontrakan',
                    'tgl_pembayaran': 1,
                    'harga_perbulan': 1,
                    'jumlah_sewa': 1,
                    'total_harga': 1,
                    'uang_bayar': 1,
                    'kembalian': 1
                }
            }
        ]

        transaksi = next(db.transaksi.aggregate(pipeline))
    except StopIteration:
        abort(404, description="Transaction not found")
    return render_template('views/admin/transaksi/detail_transaksi.html', transaksi=transaksi)

# Route edit transaksi role admin
@views_bp.route('/admin/transaksi/edit_transaksi/<transaksi_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_transaksi(transaksi_id):
    if request.method == 'POST':
        penghuni_id = request.form['penghuni']
        tgl_pembayaran = request.form['tgl_pembayaran']
        kontrakan_id = request.form['kontrakan']
        harga_perbulan = int(request.form['harga_perbulan'])
        jumlah_sewa = int(request.form['jumlah_sewa'])
        total_harga = int(request.form['total_harga'])
        uang_bayar = int(request.form['uang_bayar'])
        kembalian = int(request.form['kembalian'])
        status = request.form['status']
        bukti_pembayaran = request.files['bukti_pembayaran']

        update_data = {
            'tgl_pembayaran': tgl_pembayaran,
            'kontrakan_id': ObjectId(kontrakan_id),
            'harga_perbulan': harga_perbulan,
            'jumlah_sewa': jumlah_sewa,
            'total_harga': total_harga,
            'uang_bayar': uang_bayar,
            'kembalian': kembalian,
            'status': status,
        }

        if bukti_pembayaran and allowed_file(bukti_pembayaran.filename):
            today = datetime.now()
            my_time = today.strftime('%Y-%m-%d-%H-%M-%S')
            extension = bukti_pembayaran.filename.split('.')[-1]
            filename = secure_filename(f'bukti_pembayaran_{my_time}.{extension}')
            namaGambar = os.path.join(app.config["UPLOAD_FOLDER_TRANSAKSI"], filename)
            bukti_pembayaran.save(namaGambar)
            update_data['bukti_pembayaran'] = namaGambar

        db.transaksi.update_one({'_id': ObjectId(transaksi_id)}, {'$set': update_data})
        return redirect(url_for('views.transaksi'))

    try:
        pipeline = [
            {
                '$match': {'_id': ObjectId(transaksi_id)}
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'user_data'
                }
            },
            {
                '$lookup': {
                    'from': 'penghuni',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'penghuni_data'
                }
            },
            {
                '$addFields': {
                    'penghuni_data': {
                        '$cond': {
                            'if': { '$gt': [{ '$size': '$user_data' }, 0] },
                            'then': { '$arrayElemAt': ['$user_data', 0] },
                            'else': { '$arrayElemAt': ['$penghuni_data', 0] }
                        }
                    }
                }
            },
            {
                '$lookup': {
                    'from': 'kontrakan',
                    'localField': 'kontrakan_id',
                    'foreignField': '_id',
                    'as': 'kontrakan'
                }
            },
            {
                '$unwind': {
                    'path': '$kontrakan',
                    'preserveNullAndEmptyArrays': True
                }
            }
        ]

        transaksi = next(db.transaksi.aggregate(pipeline))
    except StopIteration:
        abort(404, description="Transaction not found")

    penghuni = db.penghuni.find()
    kontrakan = db.kontrakan.find()

    return render_template('views/admin/transaksi/edit_transaksi.html', transaksi=transaksi, penghuni=penghuni, kontrakan=kontrakan)


# Route for hapus_transaksi
@views_bp.route('/admin/transaksi/hapus_transaksi/<transaksi_id>', methods=['POST'])
@login_required
@role_required('admin')
def hapus_transaksi(transaksi_id):
    result = db.transaksi.delete_one({"_id": ObjectId(transaksi_id)})
    if result.deleted_count == 1:
        return redirect(url_for('views.transaksi'))
    else:
        return "Transaksi tidak ditemukan atau tidak dapat dihapus", 404

#  ------------------------ END TRANSAKSI ------------------------ 



#  ------------------------ Start Keluhan ------------------------ 

# Route for Keluhan page (Read all complaints)
@views_bp.route('/admin/keluhan')
@login_required
@role_required('admin')
def keluhan():
    pipeline = [
        {
            '$lookup': {
                'from': 'users',
                'localField': 'penghuni_id',
                'foreignField': '_id',
                'as': 'user_data'
            }
        },
        {
            '$lookup': {
                'from': 'penghuni',
                'localField': 'penghuni_id',
                'foreignField': '_id',
                'as': 'penghuni_data'
            }
        },
        {
            '$addFields': {
                'nama_penghuni': {
                    '$ifNull': [
                        { '$arrayElemAt': ['$user_data.nama', 0] },
                        { '$arrayElemAt': ['$penghuni_data.nama', 0] }
                    ]
                }
            }
        },
        {
            '$lookup': {
                'from': 'kontrakan',
                'localField': 'kontrakan_id',
                'foreignField': '_id',
                'as': 'kontrakan'
            }
        },
        {
            '$unwind': '$kontrakan'
        },
        {
            '$project': {
                '_id': 1,
                'keluhan_penghuni': 1,
                'tgl_keluhan': 1,
                'gambar_keluhan': 1,
                'status': 1,
                'nama_penghuni': 1,
                'nama_kontrakan': '$kontrakan.nama_kontrakan'
            }
        }
    ]

    keluhan_list = list(db.keluhan.aggregate(pipeline))

    # Print results for debugging
    for keluhan in keluhan_list:
        print(keluhan)

    return render_template('views/admin/keluhan/index.html', data_keluhan=keluhan_list)


# Route for tambah_keluhan page (Create new complaint)
@views_bp.route('/admin/keluhan/tambah_keluhan', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def tambah_keluhan():
    if request.method == 'POST':
        penghuni_id = request.form['penghuni']
        kontrakan_id = request.form['kontrakan']
        tgl_keluhan = request.form['tgl_keluhan']
        status = request.form['status']
        keluhan_penghuni = request.form['keluhan_penghuni']
        gambar_keluhan = request.files['gambar_keluhan']

        keluhan_data = {
            'penghuni_id': ObjectId(penghuni_id),
            'kontrakan_id': ObjectId(kontrakan_id),
            'tgl_keluhan': tgl_keluhan,
            'status': status,
            'keluhan_penghuni': keluhan_penghuni,
        }

        if gambar_keluhan and allowed_file(gambar_keluhan.filename):
            filename = secure_filename(gambar_keluhan.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER_KELUHAN"], filename)
            gambar_keluhan.save(file_path)
            keluhan_data['gambar_keluhan'] = file_path

        db.keluhan.insert_one(keluhan_data)
        return redirect(url_for('views.keluhan'))

    user = db.users.find()
    kontrakan = db.kontrakan.find()
    return render_template('views/admin/keluhan/tambah_keluhan.html', user=user, kontrakan=kontrakan)

# Route for edit_keluhan page (Update complaint)
@views_bp.route('/admin/keluhan/edit_keluhan/<keluhan_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_keluhan(keluhan_id):
    if request.method == 'POST':
        penghuni_id = request.form['penghuni']
        kontrakan_id = request.form['kontrakan']
        tgl_keluhan = request.form['tgl_keluhan']
        status = request.form['status']
        keluhan_penghuni = request.form['keluhan_penghuni']
        gambar_keluhan = request.files['gambar_keluhan']

        update_data = { 
            'kontrakan_id': ObjectId(kontrakan_id),
            'tgl_keluhan': tgl_keluhan,
            'status': status,
            'keluhan_penghuni': keluhan_penghuni,
        }

        if gambar_keluhan and allowed_file(gambar_keluhan.filename):
            filename = secure_filename(gambar_keluhan.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER_KELUHAN"], filename)
            gambar_keluhan.save(file_path)
            update_data['gambar_keluhan'] = file_path

        db.keluhan.update_one({'_id': ObjectId(keluhan_id)}, {'$set': update_data})
        return redirect(url_for('views.keluhan'))

    try:
        pipeline = [
            {
                '$match': {'_id': ObjectId(keluhan_id)}
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'user_data'
                }
            },
            {
                '$lookup': {
                    'from': 'penghuni',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'penghuni_data'
                }
            },
            {
                '$addFields': {
                    'penghuni_data': {
                        '$cond': {
                            'if': { '$gt': [{ '$size': '$user_data' }, 0] },
                            'then': { '$arrayElemAt': ['$user_data', 0] },
                            'else': { '$arrayElemAt': ['$penghuni_data', 0] }
                        }
                    }
                }
            },
            {
                '$lookup': {
                    'from': 'kontrakan',
                    'localField': 'kontrakan_id',
                    'foreignField': '_id',
                    'as': 'kontrakan'
                }
            },
            {
                '$unwind': {
                    'path': '$kontrakan',
                    'preserveNullAndEmptyArrays': True
                }
            },
            {
                '$project': {
                    '_id': 1,
                    'keluhan_penghuni': 1,
                    'tgl_keluhan': 1,
                    'gambar_keluhan': 1,
                    'status': 1,
                    'nama_penghuni': {
                        '$ifNull': [
                            { '$arrayElemAt': ['$user_data.nama', 0] },
                            { '$arrayElemAt': ['$penghuni_data.nama', 0] }
                        ]
                    },
                     'nama_kontrakan': '$kontrakan.nama_kontrakan',
                     'kontrakan_id': '$kontrakan._id'
                }
            }
        ]

        keluhan = next(db.keluhan.aggregate(pipeline), None)
        if not keluhan:
            abort(404, description="Complaint not found")
        
    except Exception as e:
        print(f"An error occurred: {e}")
        abort(500, description="Internal Server Error")

    penghuni = db.penghuni.find()
    kontrakan = db.kontrakan.find()

    return render_template('views/admin/keluhan/edit_keluhan.html', keluhan=keluhan, penghuni=penghuni, kontrakan=kontrakan)

 
# Route for detail_keluhan page (Read specific complaint)
@views_bp.route('/admin/keluhan/detail_keluhan/<keluhan_id>')
@login_required
@role_required('admin')
def detail_keluhan(keluhan_id):
    try:
        pipeline = [
            {
                '$match': {'_id': ObjectId(keluhan_id)}
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'user_data'
                }
            },
            {
                '$lookup': {
                    'from': 'penghuni',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'penghuni_data'
                }
            },
            {
                '$addFields': {
                    'nama_penghuni': {
                        '$ifNull': [
                            { '$arrayElemAt': ['$user_data.nama', 0] },
                            { '$arrayElemAt': ['$penghuni_data.nama', 0] }
                        ]
                    }
                }
            },
            {
                '$lookup': {
                    'from': 'kontrakan',
                    'localField': 'kontrakan_id',
                    'foreignField': '_id',
                    'as': 'kontrakan'
                }
            },
            {
                '$unwind': '$kontrakan'
            },
            {
                '$project': {
                    '_id': 1,
                    'keluhan': 1,
                    'tgl_keluhan': 1,
                    'gambar_keluhan': 1,
                    'status': 1,
                    'keluhan_penghuni': 1,
                    'nama_penghuni': 1,
                    'nama_kontrakan': '$kontrakan.nama_kontrakan'
                }
            }
        ]

        keluhan = next(db.keluhan.aggregate(pipeline), None)
        if not keluhan:
            abort(404, description="Complaint not found")
        
    except Exception as e:
        print(f"An error occurred: {e}")
        abort(500, description="Internal Server Error")
        
    return render_template('views/admin/keluhan/detail_keluhan.html', keluhan=keluhan)


# Route to delete a complaint
@views_bp.route('/admin/keluhan/delete_keluhan/<keluhan_id>', methods=['POST'])
@login_required
@role_required('admin')
def hapus_keluhan(keluhan_id):
    db.keluhan.delete_one({'_id': ObjectId(keluhan_id)})
    return redirect(url_for('views.keluhan'))

# -------------------- End Keluhan -----------------------

#  ------------------------ END BAGIAN ADMIN  ------------------------ 

 
 
  
# ------------------------ START BAGIAN PENYEWA ------------------------

#  ------------------------ START HOMEPAGE PENGHUNI ------------------------ 
from datetime import datetime
from flask import render_template
from bson import json_util
import pytz
import locale
from app import db  # Pastikan ini disesuaikan dengan struktur aplikasi Anda

@views_bp.route('/homepage')
@login_required
@role_required('penghuni')
def homepage():
    # Ambil seluruh data penghuni dari MongoDB
    penghuni_count = db.penghuni.count_documents({})
    kontrakan_count = db.kontrakan.count_documents({})
    keluhan_count = db.keluhan.count_documents({})

    # Mengambil jumlah keluhan per bulan selama 12 bulan terakhir
    keluhan_per_bulan = db.keluhan.aggregate([
        {
            "$addFields": {
                "tgl_keluhan": {
                    "$dateFromString": {
                        "dateString": "$tgl_keluhan"
                    }
                }
            }
        },
        {
            "$group": {
                "_id": {
                    "year": {"$year": "$tgl_keluhan"},
                    "month": {"$month": "$tgl_keluhan"}
                },
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {"_id.year": 1, "_id.month": 1}
        }
    ])
    keluhan_per_bulan = list(keluhan_per_bulan)
    print("Keluhan per bulan:", keluhan_per_bulan)

    # Mengambil jumlah transaksi per bulan selama 12 bulan terakhir
    transaksi_per_bulan = db.transaksi.aggregate([
        {
            "$addFields": {
                "tgl_pembayaran": {
                    "$dateFromString": {
                        "dateString": "$tgl_pembayaran"
                    }
                }
            }
        },
        {
            "$group": {
                "_id": {
                    "year": {"$year": "$tgl_pembayaran"},
                    "month": {"$month": "$tgl_pembayaran"}
                },
                "total": {"$sum": "$total_harga"}
            }
        },
        {
            "$sort": {"_id.year": 1, "_id.month": 1}
        }
    ])
    transaksi_per_bulan = list(transaksi_per_bulan)
    print("Transaksi per bulan:", transaksi_per_bulan)

    # Membuat list untuk data keluhan dan transaksi
    keluhan_data = [0] * 12
    transaksi_data = [0] * 12
    months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]

    # Mendapatkan bulan saat ini
    jakarta_tz = pytz.timezone('Asia/Jakarta')
    now = datetime.now(jakarta_tz)
    current_year = now.year
    current_month = now.month

    # Mengisi data keluhan per bulan
    for item in keluhan_per_bulan:
        year = item['_id']['year']
        month = item['_id']['month']
        month_index = (year - current_year) * 12 + month - current_month
        if -11 <= month_index <= 0:
            keluhan_data[month_index + 11] = item['count']
        print(f"Keluhan year: {year}, month: {month}, month_index: {month_index}, count: {item['count']}")

    # Mengisi data transaksi per bulan
    for item in transaksi_per_bulan:
        year = item['_id']['year']
        month = item['_id']['month']
        month_index = (year - current_year) * 12 + month - current_month
        if -11 <= month_index <= 0:
            transaksi_data[month_index + 11] = item['total']
        print(f"Transaksi year: {year}, month: {month}, month_index: {month_index}, total: {item['total']}")

    # Mengambil total transaksi
    transaksi_total = db.transaksi.aggregate([
        {
            "$group": {
                "_id": None,
                "total": {"$sum": "$total_harga"}
            }
        }
    ])
    transaksi_total = next(transaksi_total, {'total': 0})['total']

    current_date = now.strftime('%A, %d %B %Y')
    current_time = now.strftime('%H:%M')

    # Set locale sesuai dengan pengaturan lokal Anda
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')

    # Ubah nilai transaksi_total menjadi format mata uang yang diinginkan
    transaksi_total_str = locale.currency(transaksi_total, grouping=True)

    pipeline = [
        {
            '$lookup': {
                'from': 'users',
                'localField': 'penghuni_id',
                'foreignField': '_id',
                'as': 'user_data'
            }
        },
        {
            '$lookup': {
                'from': 'penghuni',
                'localField': 'penghuni_id',
                'foreignField': '_id',
                'as': 'penghuni_data'
            }
        },
        {
            '$addFields': {
                'nama_penghuni': {
                    '$ifNull': [
                        { '$arrayElemAt': ['$user_data.nama', 0] },
                        { '$arrayElemAt': ['$penghuni_data.nama', 0] }
                    ]
                }
            }
        },
        {
            '$lookup': {
                'from': 'kontrakan',
                'localField': 'kontrakan_id',
                'foreignField': '_id',
                'as': 'kontrakan'
            }
        },
        {
            '$unwind': '$kontrakan'
        },
        {
            '$project': {
                '_id': 1,
                'keluhan_penghuni': 1,
                'tgl_keluhan': 1,
                'gambar_keluhan': 1,
                'status': 1,
                'nama_penghuni': 1,
                'nama_kontrakan': '$kontrakan.nama_kontrakan'
            }
        }
    ]

    keluhan_list = list(db.keluhan.aggregate(pipeline))

    return render_template('views/penyewa/index.html',
                           current_date=current_date,
                           current_time=current_time,
                           data_keluhan=keluhan_list,
                           penghuni_count=penghuni_count,
                           kontrakan_count=kontrakan_count,
                           keluhan_count=keluhan_count,
                           transaksi_total=transaksi_total_str,
                           keluhan_per_bulan=keluhan_data,
                           transaksi_per_bulan=transaksi_data,
                           months=months
                           )


#  ------------------------ END HOMEPAGE PENGHUNI ------------------------ 



# ------------------------ START UPDATE AKUN PENGHUNI ------------------------

@views_bp.route('/penyewa/setting_akun/<user_id>', methods=['GET', 'POST'])
@login_required
@role_required('penghuni')
def update_account_penghuni(user_id):
    print(f'Debug: user_id = {user_id}')  # Tambahkan debug print
    if request.method == 'GET':
        user = db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            flash(f'Penghuni dengan ID {user_id} tidak ditemukan', 'error')
            return redirect(url_for('views.homepage'))

        return render_template('/penyewa/setting_akun/index.html', user=user)

    elif request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        nama = request.form['nama']

        update_data = {
            'email': email, 
            'nama': nama,
        }

        if password:
            pw_hash = generate_password_hash(password)
            update_data['password'] = pw_hash

        # Update data di collection users
        result = db.users.update_one({'_id': ObjectId(user_id)}, {"$set": update_data})

        if result.matched_count == 0:
            flash(f'Penghuni dengan ID {user_id} tidak ditemukan', 'error')
            return redirect(url_for('views.homepage'))

        flash('Akun penghuni dan pengguna terkait berhasil diperbarui', 'success')
        return redirect(url_for('views.update_account_penghuni', user_id=user_id))



# ------------------------ END UPDATE AKUN PENGHUNI ------------------------

# ------------------------ START KELUHAN ------------------------
# Route for Keluhan page (Read all complaints)
@views_bp.route('/penyewa/keluhan')
@login_required
@role_required('penghuni')
def penyewa_keluhan():
    if g.current_user and g.current_user.get('role') == 'penghuni':
        penghuni_id = g.current_user['_id']
        data_keluhan = db.keluhan.aggregate([
            {
                '$match': {
                    'penghuni_id': penghuni_id
                }
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'user_data'
                }
            },
            {
                '$lookup': {
                    'from': 'penghuni',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'penghuni_data'
                }
            },
            {
                '$addFields': {
                    'penghuni': {
                        '$cond': {
                            'if': { '$gt': [{ '$size': '$user_data' }, 0] },
                            'then': { '$arrayElemAt': ['$user_data', 0] },
                            'else': { '$arrayElemAt': ['$penghuni_data', 0] }
                        }
                    }
                }
            },
            {
                '$lookup': {
                    'from': 'kontrakan',
                    'localField': 'kontrakan_id',
                    'foreignField': '_id',
                    'as': 'kontrakan'
                }
            },
            {
                '$unwind': '$kontrakan'
            },
            {
                '$project': {
                    '_id': 1,
                    'keluhan_penghuni': 1,
                    'tgl_keluhan': 1,
                    'gambar_keluhan': 1,
                    'status': 1,
                    'nama_penghuni': '$penghuni.nama',
                    'nama_kontrakan': '$kontrakan.nama_kontrakan'
                }
            }
        ])

    data_keluhan = list(data_keluhan)
    print(data_keluhan)  # Debug print
    if not data_keluhan:
        logging.debug("No complaints found.")
    return render_template('views/penyewa/keluhan/index.html', data_keluhan=data_keluhan)

# Route for tambah_keluhan page (Create new complaint)
@views_bp.route('/penyewa/keluhan/tambah', methods=['GET', 'POST'])
@login_required
@role_required('penghuni')
def tambah_keluhan_penyewa():
    if request.method == 'POST':
        try:
            penghuni_id = request.form['penghuni_id']
            kontrakan_id = request.form['kontrakan']
            tgl_keluhan = request.form['tgl_keluhan']
            status = request.form['status']
            keluhan_penghuni = request.form['keluhan_penghuni']
            gambar_keluhan = request.files['gambar_keluhan']

            keluhan_data = {
                'penghuni_id': ObjectId(penghuni_id),
                'kontrakan_id': ObjectId(kontrakan_id),
                'tgl_keluhan': tgl_keluhan,
                'status': status,
                'keluhan_penghuni': keluhan_penghuni,
            }

            if gambar_keluhan and allowed_file(gambar_keluhan.filename):
                filename = secure_filename(gambar_keluhan.filename)
                file_path = os.path.join(app.config["UPLOAD_FOLDER_KELUHAN"], filename)
                gambar_keluhan.save(file_path)
                keluhan_data['gambar_keluhan'] = file_path

            db.keluhan.insert_one(keluhan_data)
            return redirect(url_for('views.penyewa_keluhan'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('views.tambah_keluhan_penyewa'))

    kontrakan = db.kontrakan.find()
    return render_template('views/penyewa/keluhan/tambah_keluhan.html', kontrakan=kontrakan)
 

@views_bp.route('/penyewa/keluhan/edit/<keluhan_id>', methods=['GET', 'POST'])
@login_required
@role_required('penghuni')
def edit_keluhan_penyewa(keluhan_id):
    if request.method == 'POST':
        try: 
            kontrakan_id = request.form['kontrakan']
            tgl_keluhan = request.form['tgl_keluhan']
            status = request.form['status']
            keluhan_penghuni = request.form['keluhan_penghuni']
            gambar_keluhan = request.files['gambar_keluhan']

            update_data = {
                'kontrakan_id': ObjectId(kontrakan_id),
                'tgl_keluhan': tgl_keluhan,
                'status': status,
                'keluhan_penghuni': keluhan_penghuni,
            }

            if gambar_keluhan and allowed_file(gambar_keluhan.filename):
                filename = secure_filename(gambar_keluhan.filename)
                file_path = os.path.join(app.config["UPLOAD_FOLDER_KELUHAN"], filename)
                gambar_keluhan.save(file_path)
                update_data['gambar_keluhan'] = file_path

            db.keluhan.update_one({'_id': ObjectId(keluhan_id)}, {'$set': update_data})
            return redirect(url_for('views.penyewa_keluhan'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('views.edit_keluhan_penyewa', keluhan_id=keluhan_id))

    keluhan = db.keluhan.find_one({'_id': ObjectId(keluhan_id)})
    if keluhan:
        penghuni = db.penghuni.find_one({'_id': keluhan['penghuni_id']})
        kontrakan = db.kontrakan.find()
        return render_template('views/penyewa/keluhan/edit_keluhan.html', keluhan=keluhan, penghuni=penghuni, kontrakan=kontrakan)
    else:
        return "Keluhan tidak ditemukan", 404

# Route for detail_keluhan page (Read specific complaint)
@views_bp.route('/penyewa/keluhan/detail_keluhan/<keluhan_id>')
@login_required
@role_required('penghuni')
def detail_keluhan_penyewa(keluhan_id):
    try:
        pipeline = [
            {
                '$match': {'_id': ObjectId(keluhan_id)}
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'user_data'
                }
            },
            {
                '$lookup': {
                    'from': 'penghuni',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'penghuni_data'
                }
            },
            {
                '$addFields': {
                    'nama_penghuni': {
                        '$ifNull': [
                            { '$arrayElemAt': ['$user_data.nama', 0] },
                            { '$arrayElemAt': ['$penghuni_data.nama', 0] }
                        ]
                    }
                }
            },
            {
                '$lookup': {
                    'from': 'kontrakan',
                    'localField': 'kontrakan_id',
                    'foreignField': '_id',
                    'as': 'kontrakan'
                }
            },
            {
                '$unwind': '$kontrakan'
            },
            {
                '$project': {
                    '_id': 1,
                    'keluhan': 1,
                    'tgl_keluhan': 1,
                    'gambar_keluhan': 1,
                    'status': 1,
                    'keluhan_penghuni': 1,
                    'nama_penghuni': 1,
                    'nama_kontrakan': '$kontrakan.nama_kontrakan'
                }
            }
        ]

        keluhan = next(db.keluhan.aggregate(pipeline), None)
        if not keluhan:
            abort(404, description="Complaint not found")
        
    except Exception as e:
        print(f"An error occurred: {e}")
        abort(500, description="Internal Server Error")
        
    return render_template('views/penyewa/keluhan/detail_keluhan.html', keluhan=keluhan)


# Route for hapus_keluhan
@views_bp.route('/penyewa/keluhan/hapus/<keluhan_id>', methods=['POST'])
@login_required
@role_required('penghuni')
def hapus_keluhan_penyewa(keluhan_id):
    try:
        db.keluhan.delete_one({"_id": ObjectId(keluhan_id)})
        flash('Keluhan berhasil dihapus', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('penyewa_keluhan'))

# ------------------------ END KELUHAN ------------------------
 
# ------------------------ START TRANSAKSI  ------------------------
# Tambah transaksi role penghuni
@views_bp.route('/penyewa/transaksi')
@login_required
@role_required('penghuni')
def penyewa_transaksi():
    if g.current_user and g.current_user.get('role') == 'penghuni':
        penghuni_id = g.current_user['_id']
        data_transaksi = db.transaksi.aggregate([
            {
                '$match': {
                    'penghuni_id': penghuni_id
                }
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'user_data'
                }
            },
            {
                '$lookup': {
                    'from': 'penghuni',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'penghuni_data'
                }
            },
            {
                '$addFields': {
                    'penghuni': {
                        '$cond': {
                            'if': { '$gt': [{ '$size': '$user_data' }, 0] },
                            'then': { '$arrayElemAt': ['$user_data', 0] },
                            'else': { '$arrayElemAt': ['$penghuni_data', 0] }
                        }
                    }
                }
            },
            {
                '$lookup': {
                    'from': 'kontrakan',
                    'localField': 'kontrakan_id',
                    'foreignField': '_id',
                    'as': 'kontrakan'
                }
            },
            {
                '$unwind': '$kontrakan'
            },
            {
                '$project': {
                    '_id': 1,
                    'bukti_pembayaran': 1,
                    'status': 1,
                    'nama_penghuni': '$penghuni.nama',
                    'nama_kontrakan': '$kontrakan.nama_kontrakan'
                }
            }
        ])

    data_transaksi = list(data_transaksi)
    print(data_transaksi)  # Debug print
    if not data_transaksi:
        logging.debug("No transactions found.")
    return render_template('views/penyewa/transaksi/index.html', list_transaksi=data_transaksi)

 
# Route for tambah_transaksi page
@views_bp.route('/penyewa/transaksi/tambah', methods=['GET', 'POST'])
@login_required
@role_required('penghuni')
def tambah_transaksi_penyewa():
    if request.method == 'POST':
        try:
            penghuni_id = request.form['penghuni_id']  # Ambil penghuni_id dari hidden input
            tgl_pembayaran = request.form['tgl_pembayaran']
            kontrakan_id = request.form['kontrakan']
            harga_perbulan = int(request.form['harga_perbulan'])
            jumlah_sewa = int(request.form['jumlah_sewa'])
            total_harga = int(request.form['total_harga'])
            uang_bayar = int(request.form['uang_bayar'])
            kembalian = int(request.form['kembalian'])
            status = request.form['status']
            bukti_pembayaran = request.files['bukti_pembayaran']

            
            if bukti_pembayaran and allowed_file(bukti_pembayaran.filename):
                today = datetime.now()
                my_time = today.strftime('%Y-%m-%d-%H-%M-%S')
                extention = bukti_pembayaran.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(f'bukti_pembayaran_{my_time}.{extention}')
                namaGambar = os.path.join(app.config["UPLOAD_FOLDER_TRANSAKSI"], filename)
                bukti_pembayaran.save(namaGambar)
            else:
                namaGambar = None

            doc = {
                'penghuni_id': ObjectId(penghuni_id),
                'tgl_pembayaran': tgl_pembayaran,
                'kontrakan_id': ObjectId(kontrakan_id),
                'harga_perbulan': harga_perbulan,
                'jumlah_sewa': jumlah_sewa,
                'total_harga': total_harga,
                'uang_bayar': uang_bayar,
                'kembalian': kembalian,
                'status': status,
                'bukti_pembayaran': namaGambar
            }

            logging.debug(f"Inserting document: {doc}")

            db.transaksi.insert_one(doc)
            logging.debug("Document inserted successfully")
            return redirect(url_for('views.penyewa_transaksi'))
        except Exception as e:
            logging.error(f"Error processing form data: {e}")
            return "There was an error processing your request.", 500

    penghuni = db.penghuni.find()
    kontrakan = db.kontrakan.find()
    return render_template('views/penyewa/transaksi/tambah_transaksi.html', penghuni=penghuni, kontrakan=kontrakan)

# Route for edit_transaksi penyewa page
@views_bp.route('/penyewa/transaksi/edit/<transaksi_id>', methods=['GET', 'POST'])
@login_required
@role_required('penghuni')
def edit_transaksi_penyewa(transaksi_id):
    if request.method == 'POST':
        penghuni_id = request.form['penghuni']
        tgl_pembayaran = request.form['tgl_pembayaran']
        kontrakan_id = request.form['kontrakan']
        harga_perbulan = int(request.form['harga_perbulan'])
        jumlah_sewa = int(request.form['jumlah_sewa'])
        total_harga = int(request.form['total_harga'])
        uang_bayar = int(request.form['uang_bayar'])
        kembalian = int(request.form['kembalian'])
        status = request.form['status']
        bukti_pembayaran = request.files['bukti_pembayaran']

        update_data = {
            'penghuni_id': ObjectId(penghuni_id),
            'tgl_pembayaran': tgl_pembayaran,
            'kontrakan_id': ObjectId(kontrakan_id),
            'harga_perbulan': harga_perbulan,
            'jumlah_sewa': jumlah_sewa,
            'total_harga': total_harga,
            'uang_bayar': uang_bayar,
            'kembalian': kembalian,
            'status': status,
        }

        if bukti_pembayaran and allowed_file(bukti_pembayaran.filename):
            today = datetime.now()
            my_time = today.strftime('%Y-%m-%d-%H-%M-%S')
            extension = bukti_pembayaran.filename.split('.')[-1]
            filename = secure_filename(f'bukti_pembayaran_{my_time}.{extension}')
            namaGambar = os.path.join(app.config["UPLOAD_FOLDER_TRANSAKSI"], filename)
            bukti_pembayaran.save(namaGambar)
            update_data['bukti_pembayaran'] = namaGambar

        db.transaksi.update_one({'_id': ObjectId(transaksi_id)}, {'$set': update_data})
        return redirect(url_for('views.transaksi'))

    transaksi = db.transaksi.aggregate([
        {
            '$match': {'_id': ObjectId(transaksi_id)}
        },
        {
            '$lookup': {
                'from': 'penghuni',
                'localField': 'penghuni_id',
                'foreignField': '_id',
                'as': 'penghuni'
            }
        },
        {
            '$lookup': {
                'from': 'kontrakan',
                'localField': 'kontrakan_id',
                'foreignField': '_id',
                'as': 'kontrakan'
            }
        },
        {
            '$unwind': '$penghuni'
        },
        {
            '$unwind': '$kontrakan'
        }
    ]).next()

    penghuni = db.penghuni.find()
    kontrakan = db.kontrakan.find()

    return render_template('views/penyewa/transaksi/edit_transaksi.html', transaksi=transaksi, penghuni=penghuni, kontrakan=kontrakan)



# Route for detail_transaksi penyewa page
@views_bp.route('/penyewa/transaksi/detail_transaksi/<transaksi_id>')
@login_required
@role_required('penghuni')
def detail_transaksi_penyewa(transaksi_id):
    try:
        pipeline = [
            {
                '$match': {
                    '_id': ObjectId(transaksi_id)
                }
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'user_data'
                }
            },
            {
                '$lookup': {
                    'from': 'penghuni',
                    'localField': 'penghuni_id',
                    'foreignField': '_id',
                    'as': 'penghuni_data'
                }
            },
            {
                '$addFields': {
                    'nama_penghuni': {
                        '$ifNull': [
                            { '$arrayElemAt': ['$user_data.nama', 0] },
                            { '$arrayElemAt': ['$penghuni_data.nama', 0] }
                        ]
                    }
                }
            },
            {
                '$lookup': {
                    'from': 'kontrakan',
                    'localField': 'kontrakan_id',
                    'foreignField': '_id',
                    'as': 'kontrakan'
                }
            },
            {
                '$unwind': '$kontrakan'
            },
            {
                '$project': {
                    '_id': 1,
                    'bukti_pembayaran': 1,
                    'status': 1,
                    'nama_penghuni': 1, 
                    'nama_kontrakan': '$kontrakan.nama_kontrakan',
                    'tgl_pembayaran': 1,
                    'harga_perbulan': 1,
                    'jumlah_sewa': 1,
                    'total_harga': 1,
                    'uang_bayar': 1,
                    'kembalian': 1
                }
            }
        ]

        transaksi = next(db.transaksi.aggregate(pipeline))
    except StopIteration:
        abort(404, description="Transaction not found")

    return render_template('views/penyewa/transaksi/detail_transaksi.html', transaksi=transaksi)


# ------------------------ END TRANSAKSI ------------------------

# ------------------------ END BAGIAN PENYEWA ------------------------ 

 

 #  --- WAJIB JANGAN DIHAPUS ---
# Register blueprint
app.register_blueprint(views_bp)


def seed_data():
    # Seed Penghuni
    penghuni_data = [
        {
            'email': 'penghuni1@example.com',
            'password': hashlib.sha256('password1'.encode("utf-8")).hexdigest(),
            'nama': 'Penghuni Satu',
            'umur': 30,
            'jenisKelamin': 'Laki-laki',
            'status': 'Aktif',
            'poto_ktp': 'static/upload/ktp/penghuni1.jpg'
        },
        {
            'email': 'penghuni2@example.com',
            'password': hashlib.sha256('password2'.encode("utf-8")).hexdigest(),
            'nama': 'Penghuni Dua',
            'umur': 25,
            'jenisKelamin': 'Perempuan',
            'status': 'Aktif',
            'poto_ktp': 'static/upload/ktp/penghuni2.jpg'
        }
    ]
    db.penghuni.insert_many(penghuni_data)

    # Seed Kontrakan
    kontrakan_data = [
        {
            'nama_kontrakan': 'Kontrakan A',
            'harga': 2000000,
            'status': 'Tersedia',
            'alamat': 'Jl. Merdeka No. 1',
            'kapasitas': 3,
            'gambar': 'static/upload/kontrakan/kontrakan_a.jpg'
        },
        {
            'nama_kontrakan': 'Kontrakan B',
            'harga': 1500000,
            'status': 'Tersedia',
            'alamat': 'Jl. Sudirman No. 2',
            'kapasitas': 2,
            'gambar': 'static/upload/kontrakan/kontrakan_b.jpg'
        }
    ]
    db.kontrakan.insert_many(kontrakan_data)

    # Seed User
    user_data = [
        {
            'email': 'admin@example.com',
            'password': generate_password_hash('adminpassword'),
            'role': 'admin',
            'nama': 'Admin User'
        },
        {
            'email': 'user@example.com',
            'password': generate_password_hash('userpassword'),
            'role': 'penghuni',
            'nama': 'Regular User'
        }
    ]
    db.users.insert_many(user_data)
 
if __name__ == '__main__': 
    # seed_data()
    app.run(debug=True)
