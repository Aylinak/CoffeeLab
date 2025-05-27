from flask import Flask, request, jsonify, redirect, url_for, session, send_file, send_from_directory
from flask_cors import CORS
import sqlite3
import hashlib
import jwt
import datetime
import os
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from oauthlib.oauth2 import WebApplicationClient
import requests
import json
import pathlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

# Geliştirme ortamında HTTPS gerekliliğini kaldır
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__, static_url_path='')
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = os.urandom(24)  # Session için gerekli
app.config['SECRET_KEY'] = 'your-secret-key-here'  # JWT için gizli anahtar

# Statik dosyaları servis et
@app.route('/images/<path:filename>')
def serve_image(filename):
    return send_from_directory('images', filename)

# Ana sayfa
@app.route('/')
def index():
    return send_file('index.html')

# Google OAuth2 bilgileri
GOOGLE_CLIENT_ID = "1051408833618-b6m8ct70ma173thu8ufcvngktqn8rnfl.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# OAuth2 client kurulumu
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Veritabanı oluşturma ve tablo kurulumu
def init_db():
    with sqlite3.connect('users.db', timeout=20) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT,
                google_id TEXT UNIQUE,
                reset_token TEXT,
                reset_token_expiry DATETIME
            )
        ''')
        conn.commit()

# Veritabanı bağlantısı için yardımcı fonksiyon
def get_db_connection():
    conn = sqlite3.connect('users.db', timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

# Şifre hashleme fonksiyonu
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Kullanıcı kaydı
@app.route('/register', methods=['POST'])
def register():
    print("Register endpoint hit!")  # Debug log
    data = request.get_json()
    print("Received data:", data)  # Debug log
    
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    
    print(f"Name: {name}, Email: {email}")  # Debug log
    
    if not all([name, email, password]):
        print("Missing required fields")  # Debug log
        return jsonify({'error': 'Tüm alanlar gereklidir'}), 400
    
    hashed_password = hash_password(password)
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                     (name, email, hashed_password))
            conn.commit()
        
        print("User successfully registered")  # Debug log
        return jsonify({'message': 'Kayıt başarılı'}), 201
    
    except sqlite3.IntegrityError:
        print("Email already exists")  # Debug log
        return jsonify({'error': 'Bu email zaten kayıtlı'}), 400
    except Exception as e:
        print("Error:", str(e))  # Debug log
        return jsonify({'error': str(e)}), 500

# Kullanıcı girişi
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    print("Login attempt with data:", data)  # Debug log
    
    email = data.get('email')
    password = data.get('password')
    
    if not all([email, password]):
        return jsonify({'error': 'Email ve şifre gereklidir'}), 400
    
    hashed_password = hash_password(password)
    print(f"Attempting login for email: {email}")  # Debug log
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id, name FROM users WHERE email = ? AND password = ?',
                     (email, hashed_password))
            user = c.fetchone()
        
        if user:
            print(f"Login successful for user: {user[1]}")  # Debug log
            # JWT token oluştur
            token = jwt.encode({
                'user_id': user[0],
                'name': user[1],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'token': token,
                'user': {
                    'id': user[0],
                    'name': user[1],
                    'email': email
                }
            }), 200
        else:
            print(f"Login failed for email: {email}")  # Debug log
            return jsonify({'error': 'Geçersiz email veya şifre'}), 401
            
    except Exception as e:
        print(f"Login error: {str(e)}")  # Debug log
        return jsonify({'error': str(e)}), 500

# Google ile giriş endpoint'i
@app.route('/auth/google')
def google_auth():
    try:
        # Google OAuth2 için yetkilendirme URL'ini oluştur
        auth_url = client.prepare_request_uri(
            "https://accounts.google.com/o/oauth2/v2/auth",
            redirect_uri=f"http://localhost:5000/auth/google/callback",
            scope=["openid", "email", "profile"],
            prompt="select_account"  # Kullanıcıya her zaman hesap seçimini göster
        )
        return jsonify({"auth_url": auth_url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Google callback endpoint'i
@app.route('/auth/google/callback')
def google_auth_callback():
    try:
        # Google'dan gelen kodu al
        code = request.args.get('code')
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        token_endpoint = google_provider_cfg["token_endpoint"]

        # Token al
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url="http://localhost:5000/auth/google/callback",
            code=code
        )
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
        )

        client.parse_request_body_response(json.dumps(token_response.json()))

        # Kullanıcı bilgilerini al
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers)

        if userinfo_response.json().get("email_verified"):
            google_id = userinfo_response.json()["sub"]
            email = userinfo_response.json()["email"]
            name = userinfo_response.json()["name"]

            # Kullanıcıyı veritabanına kaydet veya güncelle
            try:
                conn = sqlite3.connect('users.db')
                c = conn.cursor()
                c.execute('SELECT id, name FROM users WHERE google_id = ? OR email = ?',
                         (google_id, email))
                user = c.fetchone()

                if not user:
                    c.execute('INSERT INTO users (name, email, google_id) VALUES (?, ?, ?)',
                             (name, email, google_id))
                    conn.commit()
                    user_id = c.lastrowid
                else:
                    user_id = user[0]
                    if not user[1] == name:
                        c.execute('UPDATE users SET name = ? WHERE id = ?',
                                 (name, user_id))
                        conn.commit()

                conn.close()

                # JWT token oluştur
                token = jwt.encode({
                    'user_id': user_id,
                    'name': name,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
                }, app.config['SECRET_KEY'], algorithm='HS256')

                # Frontend'e yönlendir ve parametreleri query string olarak ekle
                user_data = {
                    "id": user_id,
                    "name": name,
                    "email": email,
                    "google_id": google_id
                }
                return redirect(f'/?token={token}&user={json.dumps(user_data)}')

            except Exception as e:
                print("Error in Google callback:", str(e))
                return jsonify({'error': str(e)}), 500
        else:
            return jsonify({'error': 'Google hesabı doğrulanamadı'}), 401
    except Exception as e:
        print("Error in Google callback:", str(e))
        return jsonify({'error': str(e)}), 500

def verify_token(token):
    try:
        # Token'ı doğrula ve payload'dan user_id'yi al
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/verify_token', methods=['POST'])
def verify_token_endpoint():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"valid": False}), 401
    
    token = auth_header.split(' ')[1]
    try:
        # Token'ı doğrula
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({"valid": True})
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token süresi dolmuş"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Geçersiz token"}), 401

@app.route('/data-deletion', methods=['GET', 'POST'])
def data_deletion():
    if request.method == 'POST':
        return jsonify({
            "url": "https://localhost:5000/data-deletion",
            "confirmation_code": "COFFEE_LAB_DATA_DELETED_" + str(datetime.datetime.now().timestamp()),
            "status": "success"
        })
    else:
        return """
        <html>
            <head><title>Data Deletion Instructions</title></head>
            <body>
                <h1>Data Deletion Instructions</h1>
                <p>To delete your data from CoffeeLab, please follow these steps:</p>
                <ol>
                    <li>Log into your account</li>
                    <li>Go to Settings</li>
                    <li>Click on "Delete Account"</li>
                </ol>
            </body>
        </html>
        """

# Şifre sıfırlama token'ı oluşturma fonksiyonu
def generate_reset_token():
    return secrets.token_urlsafe(32)

# Şifre sıfırlama token'ı kaydetme
def save_reset_token(email, token, expiry):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?',
                 (token, expiry, email))
        conn.commit()

# Şifre sıfırlama isteği endpoint'i
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email adresi gereklidir'}), 400
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE email = ?', (email,))
            user = c.fetchone()
            
            if not user:
                return jsonify({'error': 'Bu email adresi ile kayıtlı kullanıcı bulunamadı'}), 404
            
            # Geçici şifre oluştur
            temp_password = secrets.token_urlsafe(8)  # 8 karakterlik güvenli rastgele şifre
            hashed_password = hash_password(temp_password)
            
            # Kullanıcının şifresini güncelle
            c.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
            conn.commit()

            # Email gönderme
            smtp_server = "smtp.gmail.com"
            port = 587
            sender_email = "thecoffeelab3@gmail.com"
            smtp_password = "yurm cjlt urtk qmgi"
            
            message = MIMEMultipart()
            message["From"] = "CoffeeLab <thecoffeelab3@gmail.com>"
            message["To"] = email
            message["Subject"] = "CoffeeLab - Yeni Şifreniz"
            
            body = f"""
            Değerli Müşterimiz,

            CoffeeLab hesabınız için şifre sıfırlama talebiniz başarıyla alınmıştır.
            Hesabınıza erişim için geçici şifreniz aşağıda yer almaktadır:

            {temp_password}

            Güvenliğiniz için, hesabınıza giriş yaptıktan sonra "Profil" bölümünden şifrenizi değiştirmenizi önemle rica ederiz.

            Herhangi bir sorunuz olması durumunda, müşteri hizmetlerimiz ile iletişime geçebilirsiniz.

            Saygılarımızla,
            CoffeeLab Müşteri Hizmetleri
            """
            
            message.attach(MIMEText(body, "plain", "utf-8"))
            
            with smtplib.SMTP(smtp_server, port) as server:
                server.starttls()
                server.login(sender_email, smtp_password)
                text = message.as_string()
                server.sendmail(sender_email, email, text)
            
            return jsonify({
                'message': 'Yeni şifreniz email adresinize gönderildi. Lütfen email kutunuzu kontrol edin.'
            }), 200
            
    except Exception as e:
        print(f"Veritabanı hatası: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Şifre sıfırlama endpoint'i
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    if not all([token, new_password]):
        return jsonify({'error': 'Token ve yeni şifre gereklidir'}), 400
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id, email FROM users WHERE reset_token = ? AND reset_token_expiry > ?',
                     (token, datetime.datetime.utcnow()))
            user = c.fetchone()
            
            if not user:
                return jsonify({'error': 'Geçersiz veya süresi dolmuş token'}), 400
            
            # Şifreyi güncelle
            hashed_password = hash_password(new_password)
            c.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
                     (hashed_password, user[0]))
            conn.commit()
            
            return jsonify({'message': 'Şifreniz başarıyla güncellendi'}), 200
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/update-password', methods=['POST'])
def update_password():
    try:
        # Token kontrolü
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token gerekli'}), 401
        
        token = token.split(' ')[1]
        
        # Token'dan kullanıcı bilgilerini al
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Geçersiz veya süresi dolmuş token'}), 401
        
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Tüm alanlar gerekli'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Mevcut şifreyi kontrol et
            cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            
            if not user:
                return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
                
            # Mevcut şifreyi hash'leyip kontrol et
            current_hashed = hash_password(current_password)
            if current_hashed != user[0]:
                return jsonify({'error': 'Mevcut şifre yanlış'}), 401
            
            # Yeni şifreyi hashle ve güncelle
            new_hashed = hash_password(new_password)
            cursor.execute('UPDATE users SET password = ? WHERE id = ?', (new_hashed, user_id))
            conn.commit()
            
            return jsonify({'message': 'Şifre başarıyla güncellendi'}), 200
            
    except Exception as e:
        print(f"Hata: {str(e)}")
        return jsonify({'error': 'Bir hata oluştu'}), 500

if __name__ == '__main__':
    init_db()  # Veritabanını başlat
    app.run(debug=True, host='localhost', port=5000)