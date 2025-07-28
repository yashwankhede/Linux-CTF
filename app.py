import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask import Flask, render_template, request, redirect, session, send_from_directory, flash, jsonify, send_file
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from google.cloud import storage
from dotenv import load_dotenv
import io
import os
import json
import requests

# Load environment
load_dotenv()

# Firebase Admin Initialization
cred = credentials.Certificate("/etc/secrets/firebase_key.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# App config
app = Flask(__name__)
app.secret_key = 'key_to_success'  # Replace this in production

# Constants
VALID_INVITE = os.getenv("INVITE_CODE")
bucket_name = 'gcl-profile-storage'
storage_client = storage.Client()

@app.route('/')
def invite_page():
    return render_template('invite.html')

@app.route('/verify-invite', methods=['POST'])
def verify_invite():
    code = request.form.get('invite', '')
    if code == VALID_INVITE:
        session['invite'] = True
        return redirect('/register')
    return render_template('invite.html', error="Invalid invite code.")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not session.get('invite'):
        return "Access denied. Please enter a valid invite code first.", 403

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if len(password) < 8 or password.isalpha() or password.isdigit():
            return render_template('register.html', error="Password must be strong (letters + numbers + 8+ chars)")

        try:
            try:
                auth.get_user_by_email(email)
                return render_template('register.html', error="Email already exists.")
            except firebase_admin.auth.UserNotFoundError:
                pass

            user = auth.create_user(email=email, password=password, display_name=username)

            db.collection('users').document(user.uid).set({
                'uid': user.uid,
                'email': email,
                'username': username,
                'streak': 0,
                'modules_completed': 0,
                'created_at': firestore.SERVER_TIMESTAMP
            })

            api_key = os.getenv("FIREBASE_API_KEY")
            signin_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            sign_resp = requests.post(signin_url, json={
                "email": email,
                "password": password,
                "returnSecureToken": True
            })

            if sign_resp.status_code != 200:
                return render_template("register.html", error="Failed to initiate email verification.")

            id_token = sign_resp.json()["idToken"]
            verify_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}"
            requests.post(verify_url, json={"requestType": "VERIFY_EMAIL", "idToken": id_token})

            return render_template('verify.html', email=email)

        except Exception as e:
            return render_template('register.html', error=str(e))

    return render_template('register.html')

@app.route('/robots.txt')
def robots():
    return send_from_directory('static', 'robots.txt', mimetype='text/plain')

@app.route('/.hidden/<path:filename>')
def hidden_file(filename):
    return send_from_directory('static/.hidden', filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['email']
        password = request.form['password']

        try:
            if '@' not in identifier:
                users = db.collection('users').where('username', '==', identifier).stream()
                user_doc = next(users, None)
                if not user_doc:
                    return render_template('login.html', error="Username not found.")
                identifier = user_doc.to_dict()['email']
        except Exception as e:
            return render_template('login.html', error=str(e))

        try:
            api_key = os.getenv("FIREBASE_API_KEY")
            login_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            resp = requests.post(login_url, json={"email": identifier, "password": password, "returnSecureToken": True})
            if resp.status_code == 200:
                data = resp.json()
                id_token = data['idToken']
                lookup_url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"
                lookup_resp = requests.post(lookup_url, json={"idToken": id_token})
                if lookup_resp.status_code == 200:
                    user_info = lookup_resp.json().get("users", [])[0]
                    if not user_info.get("emailVerified", False):
                        return render_template('login.html', error="Please verify your email before logging in.")
                else:
                    return render_template('login.html', error="Failed to verify email status.")

                session['uid'] = data['localId']
                return redirect('/dashboard')

            return render_template('login.html', error="Invalid credentials.")

        except Exception as e:
            return render_template('login.html', error=str(e))

    return render_template('login.html')

@app.route('/check-username')
def check_username():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({"available": False})
    users = db.collection('users').where('username', '==', username).stream()
    taken = any(users)
    return jsonify({"available": not taken})

@app.route('/submit-flag', methods=['POST'])
def submit_flag():
    if 'uid' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user_id = session['uid']
    submitted_flag = request.form.get('flag', '').strip()

    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        return jsonify({"success": False, "message": "User not found"}), 404
    user_data = user_doc.to_dict()
    last_completed = user_data.get('last_completed_level', 0)
    next_level = last_completed + 1

    flag_doc = db.collection('flags').document(f'easy-matrix{next_level}').get()
    if not flag_doc.exists:
        return jsonify({"success": False, "message": "Flag not configured"}), 500
    correct_flag = flag_doc.to_dict().get('flag')

    if submitted_flag == correct_flag:
        db.collection('users').document(user_id).update({
            'last_completed_level': next_level
        })

        today_str = datetime.utcnow().strftime('%Y-%m-%d')
        blob = storage_client.bucket(bucket_name).blob(f'user_streaks/{user_id}.json')
        if blob.exists():
            streak_data = json.loads(blob.download_as_text())
        else:
            streak_data = {}
        streak_data[today_str] = True
        blob.upload_from_string(json.dumps(streak_data), content_type='application/json')

        return jsonify({"success": True, "message": f"Level {next_level} completed!"})
    else:
        return jsonify({"success": False, "message": "Incorrect flag. Try again!"})

@app.route('/dashboard')
def dashboard():
    if 'uid' not in session:
        return redirect('/login')
    user_id = session['uid']
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        return redirect('/login')
    user_data = user_doc.to_dict()
    last_completed = user_data.get('last_completed_level', 0)
    return render_template('dashboard.html', last_completed_level=last_completed)

@app.route('/profile')
def profile():
    if 'uid' not in session:
        return redirect('/login')
    
    uid = session['uid']
    user_doc = db.collection('users').document(uid).get()
    if not user_doc.exists:
        return "User not found", 404

    user_data = user_doc.to_dict()

    streak_blob = storage_client.bucket(bucket_name).blob(f'user_streaks/{uid}.json')
    if streak_blob.exists():
        streak_data = json.loads(streak_blob.download_as_text())
    else:
        streak_data = {}

    today = datetime.utcnow().date()
    start_date = today - timedelta(days=today.weekday() + 364)  # go back 1 year aligned to Monday
    grid = []

    for i in range(371):  # slightly more than 365 to align visually
        day = start_date + timedelta(days=i)
        grid.append({
            "date": str(day),
            "active": streak_data.get(str(day), False)
        })

    user_data["streak_grid"] = grid
    return render_template(
        'profile.html',
        user=user_data,
        streak_data=user_data["streak_grid"],
        start_year=start_date.year,
        current_year=today.year
    )

@app.route('/upload-photo', methods=['POST'])
def upload_photo():
    if 'uid' not in session:
        return redirect('/login')
    
    file = request.files.get('photo')
    if not file:
        return redirect('/profile')

    uid = session['uid']
    filename = secure_filename(f"{uid}.jpg")
    blob = storage_client.bucket(bucket_name).blob(f"profile_photos/{filename}")
    blob.upload_from_file(file, content_type='image/jpeg')

    return redirect('/profile')

@app.route('/profile-photo/<uid>')
def get_profile_photo(uid):
    blob = storage_client.bucket(bucket_name).blob(f'profile_photos/{uid}.jpg')
    if not blob.exists():
        return send_file('static/default.jpg', mimetype='image/jpeg')
    photo_stream = io.BytesIO()
    blob.download_to_file(photo_stream)
    photo_stream.seek(0)
    return send_file(photo_stream, mimetype='image/jpeg')

@app.route('/users')
def all_users():
    users_ref = db.collection('users').stream()
    users = []
    for doc in users_ref:
        user = doc.to_dict()
        users.append({
            "username": user.get("username"),
            "level": user.get("last_completed_level", 0),
            "uid": user.get("uid")
        })
    users.sort(key=lambda x: x["level"], reverse=True)
    return render_template("leaderboard.html", users=users)

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'uid' not in session:
        return redirect('/login')
    
    uid = session['uid']
    user_doc = db.collection('users').document(uid).get()
    if not user_doc.exists:
        return "User not found", 404
    
    user = user_doc.to_dict()

    if request.method == 'POST':
        new_email = request.form.get('new_email', '').strip()
        password = request.form.get('password', '').strip()

        if not new_email or not password:
            flash("Email and password are required.")
            return redirect('/settings')

        # Sign in to get ID token
        api_key = os.getenv("FIREBASE_API_KEY")
        sign_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        sign_resp = requests.post(sign_url, json={
            "email": user['email'],
            "password": password,
            "returnSecureToken": True
        })
        if sign_resp.status_code != 200:
            flash("Re-authentication failed.")
            return redirect('/settings')

        id_token = sign_resp.json()['idToken']

        # Request email change with verification
        verify_url = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        change_resp = requests.post(verify_url, json={
            "idToken": id_token,
            "email": new_email,
            "returnSecureToken": True
        })

        if change_resp.status_code == 200:
            flash("Verification email sent to your new address. Please verify to complete the change.")
        else:
            flash("Email update failed.")

    return render_template('settings.html', user=user)

@app.route('/change-email', methods=['POST'])
def change_email():
    if 'uid' not in session:
        return redirect('/login')

    uid = session['uid']
    new_email = request.form.get('new_email')
    current_password = request.form.get('current_password')

    user_doc = db.collection('users').document(uid).get()
    if not user_doc.exists:
        return "User not found", 404

    user_data = user_doc.to_dict()
    current_email = user_data.get("email")

    api_key = os.getenv("FIREBASE_API_KEY")

    # Step 1: Authenticate user with current password
    signin_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    auth_resp = requests.post(signin_url, json={
        "email": current_email,
        "password": current_password,
        "returnSecureToken": True
    })

    if auth_resp.status_code != 200:
        return render_template("settings.html", user=user_data, error="Current password incorrect.")

    id_token = auth_resp.json()["idToken"]

    # Step 2: Send verification email for new email
    update_url = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
    update_resp = requests.post(update_url, json={
        "idToken": id_token,
        "email": new_email,
        "returnSecureToken": True
    })

    if update_resp.status_code != 200:
        return render_template("settings.html", user=user_data, error="Email change failed.")

    # Step 3: Update Firestore after verification sent
    db.collection('users').document(uid).update({"email": new_email})

    return render_template("settings.html", user=user_data, success="Verification email sent to new address.")