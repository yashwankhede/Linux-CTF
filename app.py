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

        # Password strength validation
        if len(password) < 8 or password.isalpha() or password.isdigit():
            return render_template('register.html', error="Password must be strong (letters + numbers + 8+ chars)")

        try:
            # Create Firebase Auth user
            user = auth.create_user(email=email, password=password, display_name=username)

            # Create Firestore user document
            db.collection('users').document(user.uid).set({
                'uid': user.uid,
                'email': email,
                'username': username,
                'streak': 0,
                'modules_completed': 0,
                'created_at': firestore.SERVER_TIMESTAMP
            })

            return f"<h3>Account for {username} registered successfully ✅</h3>"

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