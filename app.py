import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask import Flask, render_template, request, redirect, session, send_from_directory, flash, jsonify
import json
import os

# Firebase Admin Initialization
cred = credentials.Certificate("/etc/secrets/firebase_key.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

app = Flask(__name__)
app.secret_key = 'key_to_success'  # Change this in production!

VALID_INVITE = "GCL{L3t_5t4rt_7h3_g4m3}"

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
            # Check if email already exists
            try:
                auth.get_user_by_email(email)
                return render_template('register.html', error="Email already exists.")
            except firebase_admin.auth.UserNotFoundError:
                pass  # Good to proceed

            # Create user
            user = auth.create_user(email=email, password=password, display_name=username)

            # Add to Firestore
            db.collection('users').document(user.uid).set({
                'uid': user.uid,
                'email': email,
                'username': username,
                'streak': 0,
                'modules_completed': 0,
                'created_at': firestore.SERVER_TIMESTAMP
            })

            # Trigger email verification using Firebase Identity Toolkit API
            import requests
            api_key = os.getenv("FIREBASE_API_KEY")
            verify_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}"
            payload = {
                "requestType": "VERIFY_EMAIL",
                "idToken": requests.post(
                    f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}",
                    json={"email": email, "password": password, "returnSecureToken": True}
                ).json()["idToken"]
            }
            requests.post(verify_url, json=payload)

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

if __name__ == '__main__':
    app.run(debug=True)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            # Simulate Firebase login by using a custom endpoint
            # Firebase Admin SDK doesn't support password verification
            import requests
            firebase_api_key = os.getenv("FIREBASE_API_KEY")  # Add this env var to Render
            login_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={firebase_api_key}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            resp = requests.post(login_url, json=payload)
            if resp.status_code == 200:
                user_data = resp.json()
                session['uid'] = user_data['localId']
                return f"<h3>Login successful! Welcome UID: {user_data['localId']}</h3>"
            else:
                return render_template('login.html', error="Invalid email or password.")

        except Exception as e:
            return render_template('login.html', error=str(e))

    return render_template('login.html')