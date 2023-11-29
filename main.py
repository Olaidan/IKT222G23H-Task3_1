from flask import Flask, render_template, request, redirect, url_for, g, session
import sqlite3
import os
import flask_limiter.util
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(24)
# Used for password hashing
bcrypt = Bcrypt()

# Used to limit login attempts, paste code here
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "50 per hour"],
    storage_uri="memory://",
)

DATABASE = 'reviews.db'
USERS_DATABASE = 'users.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def get_users_db():
    db = getattr(g, '_users_database', None)
    if db is None:
        db = g._users_database = sqlite3.connect(USERS_DATABASE)
    return db


@app.teardown_appcontext
def close_db_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

    users_db = getattr(g, '_users_database', None)
    if users_db is not None:
        users_db.close()


@app.route('/')
def index():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT rating, review_text FROM reviews')
    reviews = cursor.fetchall()

    user_id = session.get('user_id')

    sanitized_reviews = [(rating, review.replace('<', '&lt;')) for rating, review in reviews]

    return render_template('index.html', reviews=sanitized_reviews, user_id=user_id)


@app.route('/submit', methods=['POST'])
def submit_review():
    if request.method == 'POST':
        rating = request.form.get('rating')
        review_text = request.form.get('review_text')
        user_id = session.get('user_id')

        # Checks if user is logged in and for content
        if rating and review_text and user_id:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("INSERT INTO reviews (user_id, rating, review_text) VALUES (?, ?, ?)", (user_id, rating, review_text))
            db.commit()
        else:
            # Sends user to login page if attempting to submit while not logged in
            return redirect(url_for('login'))

    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username and password:
            users_db = get_users_db()
            cursor = users_db.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                return "Username already exists. Please choose a different username."

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            users_db.commit()

            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("6 per minute", override_defaults=False)  # Limit login attempts to 3 per minute, need to divide value by two to get true value
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username and password:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, password))
            user = cursor.fetchone()

            if user:
                user_id = user[0]
                session['user_id'] = user_id
                return redirect(url_for('index'))
            else:
                # Increment failed login attempts counter
                limiter.request_rate_over_limit_callback = too_many_requests
                return render_template('ratelimit.html')

    return render_template('login.html')


def too_many_requests(e):
    return render_template('ratelimit.html'), 429


if __name__ == '__main__':
    app.run(debug=True)
