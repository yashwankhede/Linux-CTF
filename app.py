import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask import Flask, render_template, request, redirect, session, send_from_directory, flash, jsonify, send_file
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from google.cloud import storage
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from google.cloud import firestore
import io
import os
import json
import requests
import calendar

# Load environment
load_dotenv()

def build_year_heatmap(dates_set, year):
    # Returns: list of months -> list of day dicts {date_str, active}
    months = []
    for m in range(1, 13):
        days = []
        _, last_day = calendar.monthrange(year, m)
        for d in range(1, last_day + 1):
            ds = datetime(year, m, d, tzinfo=timezone.utc).date().isoformat()
            days.append({
                "date": ds,
                "active": (ds in dates_set)
            })
        months.append({
            "month": m,
            "days": days
        })
    return months

def mark_streak_for_today(uid: str):
    """Mark today's date as active in user's streak (idempotent)."""
    today = datetime.now(timezone.utc).date().isoformat()  # 'YYYY-MM-DD'
    db.collection("users").document(uid).set({
        "streak_dates": {today: True},                     # map of date->True
        "streak_last_updated": firestore.SERVER_TIMESTAMP
    }, merge=True)

# streak computation utility
def _compute_consecutive_days(dates_set, today):
    # Count back from today while dates exist
    count = 0
    d = today
    while d.isoformat() in dates_set:
        count += 1
        d = d - timedelta(days=1)
    return count

# Firebase Admin Initialization
cred = credentials.Certificate("/etc/secrets/firebase_key.json")
firebase_admin.initialize_app(cred)
db = firestore.Client()

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

        api_key = os.getenv("FIREBASE_API_KEY")
        login_email = identifier

        try:
            user_uid = None
            if '@' not in identifier:
                # 🔍 Username entered — resolve to email from Firestore
                users = db.collection('users').where('username', '==', identifier).stream()
                user_doc = next(users, None)
                if not user_doc:
                    return render_template('login.html', error="Username not found.")
                user_data = user_doc.to_dict()
                login_email = user_data['email']
                user_uid = user_data['uid']

            # 🔐 Login using Firebase Identity Toolkit
            signin_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            signin_resp = requests.post(signin_url, json={
                "email": login_email,
                "password": password,
                "returnSecureToken": True
            })

            if signin_resp.status_code != 200:
                return render_template('login.html', error="Invalid credentials.")

            signin_data = signin_resp.json()
            id_token = signin_data['idToken']
            local_id = signin_data['localId']

            # 🔎 Check if email is verified
            lookup_url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"
            lookup_resp = requests.post(lookup_url, json={"idToken": id_token})
            if lookup_resp.status_code != 200:
                return render_template('login.html', error="Unable to validate email verification.")

            user_info = lookup_resp.json()["users"][0]
            if not user_info.get("emailVerified", False):
                return render_template('login.html', error="Please verify your email before logging in.")

            # ✅ Update Firestore email field if needed
            updated_email = user_info.get("email")
            db.collection('users').document(local_id).update({
                "email": updated_email
            })

            session['uid'] = local_id
            return redirect('/dashboard')

        except Exception as e:
            return render_template('login.html', error=f"Login failed: {str(e)}")

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
    data = request.get_json()
    submitted_flag = data.get("flag", "").strip()
    level = data.get("level", 0)

    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return jsonify({"success": False, "message": "User not found"}), 404

    user_data = user_doc.to_dict()
    last_completed = user_data.get('last_completed_level', 0)

    if level != last_completed + 1:
        return jsonify({"success": False, "message": "Invalid level progression"}), 403

    flag_doc = db.collection('flags').document(f'easy-matrix{level}').get()
    if not flag_doc.exists:
        return jsonify({"success": False, "message": "Flag not configured"}), 500

    correct_flag = flag_doc.to_dict().get('flag')

    if submitted_flag != correct_flag:
        return jsonify({"success": False, "message": "Incorrect flag. Try again!"})

    # ✅ Update level and streak
    today = datetime.now(timezone.utc).date()
    today_str = today.isoformat()

    updates = {
        'last_completed_level': level,
        'streak_dates': firestore.ArrayUnion([today_str]),
        'streak_last_marked': today_str
    }

    user_ref.update(updates)

    # 🔁 Recompute streak
    fresh = user_ref.get().to_dict() or {}
    dates = set(fresh.get('streak_dates', []))
    streak_count = _compute_consecutive_days(dates, today)

    user_ref.update({'streak_count': streak_count})

    return jsonify({"success": True, "message": f"Level {level} completed!"})
    
@app.route('/dashboard')
def dashboard():
    if 'uid' not in session:
        return redirect('/login')
    user_id = session['uid']
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        return redirect('/login')
    user = db.collection('users').document(session['uid']).get().to_dict() or {}
    dates = set(user.get('streak_dates', []))
    year = datetime.now(timezone.utc).year

    heatmap = build_year_heatmap(dates, year)

    return render_template(
        'dashboard.html',
        last_completed_level=user.get('last_completed_level', 0),
        streak_count=user.get('streak_count', 0),
        streak_heatmap=heatmap,
        streak_year=year
    )

from datetime import datetime, timedelta, timezone

@app.route('/profile')
def profile():
    if 'uid' not in session:
        return redirect('/login')

    uid = session['uid']
    snap = db.collection('users').document(uid).get()
    if not snap.exists:
        return "User not found", 404
    user = snap.to_dict() or {}

    # --- year selection (defaults to current UTC year) ---
    try:
        selected_year = int(request.args.get('year', datetime.now(timezone.utc).year))
    except ValueError:
        selected_year = datetime.now(timezone.utc).year

    # --- gather streak dates from Firestore first, else from the legacy GCS JSON ---
    # Firestore array: users/{uid}.streak_dates == ["YYYY-MM-DD", ...]
    firestore_dates = set(user.get('streak_dates', []) or [])
    streak_dates = set()

    if firestore_dates:
        streak_dates = firestore_dates
    else:
        # Legacy GCS blob: user_streaks/{uid}.json -> {"YYYY-MM-DD": true, ...}
        blob = storage_client.bucket(bucket_name).blob(f'user_streaks/{uid}.json')
        if blob.exists():
            try:
                raw = json.loads(blob.download_as_text())
                streak_dates = {d for d, v in raw.items() if v}
            except Exception:
                streak_dates = set()

    # Build year options (from earliest streak year to current year)
    if streak_dates:
        earliest_year = min(int(d[:4]) for d in streak_dates if len(d) >= 4 and d[:4].isdigit())
    else:
        earliest_year = datetime.now(timezone.utc).year
    current_year = datetime.now(timezone.utc).year
    year_options = list(range(current_year, earliest_year - 1, -1)) or [current_year]

    # --- compute calendar bounds like GitHub (Sun..Sat columns covering the whole year) ---
    jan1 = datetime(selected_year, 1, 1).date()
    dec31 = datetime(selected_year, 12, 31).date()

    # weekday(): Mon=0 .. Sun=6
    # first Sunday on/before Jan 1
    days_back_to_sun = (jan1.weekday() + 1) % 7
    start_date = jan1 - timedelta(days=days_back_to_sun)

    # last Saturday on/after Dec 31
    days_fwd_to_sat = (5 - dec31.weekday()) % 7  # Saturday = 5
    end_date = dec31 + timedelta(days=days_fwd_to_sat)

    # Grid we pass to the template (mostly unused for logic, helpful for debugging)
    total_days = (end_date - start_date).days + 1
    grid = []
    for i in range(total_days):
        d = start_date + timedelta(days=i)
        iso = d.isoformat()
        grid.append({"date": iso, "active": (iso in streak_dates)})

    user["streak_grid"] = grid

    return render_template(
        "profile.html",
        user=user,
        selected_year=selected_year,
        year_options=year_options,
        # set of ISO dates that should be ON
        streak_dates=list(streak_dates),
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

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'uid' not in session:
        return redirect('/login')
    
    user_id = session['uid']
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        return "User not found", 404
    user_data = user_doc.to_dict()

    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if new_password and new_password == confirm_password:
            # Authenticate again to get idToken
            api_key = os.getenv("FIREBASE_API_KEY")
            login_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            email = user_data.get("email")
            current_password = request.form.get('current_password', '').strip()

            login_resp = requests.post(login_url, json={
                "email": email,
                "password": current_password,
                "returnSecureToken": True
            })

            if login_resp.status_code == 200:
                id_token = login_resp.json().get("idToken")
                update_url = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
                update_resp = requests.post(update_url, json={
                    "idToken": id_token,
                    "password": new_password,
                    "returnSecureToken": True
                })

                if update_resp.status_code == 200:
                    flash("Password updated successfully.")
                else:
                    flash("Failed to update password.")
            else:
                flash("Current password is incorrect.")
        elif new_password != confirm_password:
            flash("Passwords do not match.")

        return redirect("/settings")

    return render_template("settings.html", user=user_data)

@app.route('/change-email', methods=['POST'])
def change_email():
    if 'uid' not in session:
        return redirect('/login')

    new_email = request.form.get("new_email", "").strip()
    current_password = request.form.get("current_password", "").strip()
    uid = session['uid']

    try:
        user_doc = db.collection('users').document(uid).get()
        if not user_doc.exists:
            return render_template("settings.html", error="User not found.", user={})

        user_data = user_doc.to_dict()
        current_email = user_data.get("email")

        api_key = os.getenv("FIREBASE_API_KEY")
        signin_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        signin_resp = requests.post(signin_url, json={
            "email": current_email,
            "password": current_password,
            "returnSecureToken": True
        })

        if signin_resp.status_code != 200:
            return render_template("settings.html", error="Current password is incorrect.", user=user_data)

        id_token = signin_resp.json().get("idToken")

        # Check if new email already exists
        try:
            auth.get_user_by_email(new_email)
            return render_template("settings.html", error="New email is already in use.", user=user_data)
        except firebase_admin.auth.UserNotFoundError:
            pass  # Good — continue

        # Send verification email to new email
        verify_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}"
        payload = {
            "requestType": "VERIFY_AND_CHANGE_EMAIL",
            "idToken": id_token,
            "newEmail": new_email,
            "continueUrl": "http://localhost:5000/confirm-email-change"
        }
        print("DEBUG payload:", payload)
        verify_resp = requests.post(verify_url, json=payload)

        print("EMAIL VERIFY LINK RESPONSE:", verify_resp.json())

        if verify_resp.status_code != 200:
            error_msg = verify_resp.json().get("error", {}).get("message", "Failed to send verification link.")
            return render_template("settings.html", error=error_msg, user=user_data)

        # Show updated email in UI until confirmed
        user_data['email'] = new_email

        return render_template("settings.html", success=f"A verification link has been sent to {new_email}", user=user_data)

    except Exception as e:
        return render_template("settings.html", error=str(e), user=user_data)

@app.route('/confirm-email-change')
def confirm_email_change():
    try:
        flash("✅ Email verified successfully. Please log in again to continue.")
        return redirect('/login')
    except Exception as e:
        return render_template("login.html", error=f"Email verified but syncing failed: {str(e)}")
        
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)