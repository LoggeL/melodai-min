import random
import deezer
from flask import Flask, redirect, request, jsonify, send_from_directory, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import os
import replicate
import requests
import json
import sqlite3
from functools import wraps
import time
from datetime import datetime, timedelta
import secrets
from helpers import chunk_lyrics, merge_lyrics
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# env
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")
app.permanent_session_lifetime = timedelta(days=30)

print("Starting Deezer")
deezer.init_deezer_session()
deezer.test_deezer_login()


def get_db():
    db = sqlite3.connect("src/database.db")
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource("schema.sql", mode="r") as f:
            db.cursor().executescript(f.read())
        db.commit()


def migrate_db():
    with app.app_context():
        db = get_db()
        try:
            # Check if last_online column exists
            db.execute("SELECT last_online FROM users LIMIT 1")
        except sqlite3.OperationalError:
            print("Adding last_online column to users table")
            db.execute("ALTER TABLE users ADD COLUMN last_online TIMESTAMP")
            db.commit()

        try:
            # Check if email column exists
            db.execute("SELECT email FROM users LIMIT 1")
        except sqlite3.OperationalError:
            print("Adding email column to users table")
            db.execute("ALTER TABLE users ADD COLUMN email TEXT")
            db.commit()

        try:
            # Add password_resets table if it doesn't exist
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS password_resets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """
            )
            db.commit()
        except sqlite3.OperationalError as e:
            print(f"Migration error: {e}")

        try:
            # Add auth_tokens table if it doesn't exist
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_tokens (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """
            )
            db.commit()
        except sqlite3.OperationalError as e:
            print(f"Migration error: {e}")


if not os.path.isfile("src/database.db"):
    init_db()
else:
    migrate_db()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            # Check for token in cookie
            token = request.cookies.get("auth_token")
            if token:
                db = get_db()
                token_data = db.execute(
                    """
                    SELECT user_id, expires_at 
                    FROM auth_tokens 
                    WHERE token = ?
                    """,
                    (token,),
                ).fetchone()

                print(token_data)

                if (
                    token_data
                    and datetime.strptime(
                        token_data["expires_at"], "%Y-%m-%d %H:%M:%S.%f"
                    )
                    > datetime.now()
                ):
                    session["user_id"] = token_data["user_id"]
                    return f(*args, **kwargs)

            # Redirect to login
            return redirect("/login?next=" + request.path)
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get("auth_token")

        if not token:
            return redirect("/login?next=" + request.path)

        db = get_db()
        token_data = db.execute(
            """
            SELECT user_id FROM auth_tokens WHERE token = ?
            """,
            (token,),
        ).fetchone()

        if not token_data:
            return redirect("/login?next=" + request.path)

        user = db.execute(
            """
            SELECT is_admin FROM users WHERE id = ?
            """,
            (token_data["user_id"],),
        ).fetchone()

        if not user or not user["is_admin"]:
            return jsonify({"error": "Admin access required"}), 403

        return f(*args, **kwargs)

    return decorated_function


@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    db = get_db()

    # if first user, make them admin
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        is_admin = True
        is_approved = True
    else:
        is_admin = False
        is_approved = False

    try:
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin, is_approved) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), is_admin, is_approved),
        )
        db.commit()
        return jsonify({"message": "Registration successful. Waiting for approval."})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    remember_me = data.get("remember_me", False)

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if user and check_password_hash(user["password_hash"], password):
        if not user["is_approved"]:
            return jsonify({"error": "Account pending approval"}), 403

        session["user_id"] = user["id"]
        response = jsonify(
            {
                "message": "Login successful",
                "is_admin": user["is_admin"],
            }
        )

        if remember_me:
            token = generate_auth_token()
            expires = datetime.now() + timedelta(days=30)

            db.execute(
                "INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
                (token, user["id"], expires),
            )
            db.commit()

            response.set_cookie(
                "auth_token",
                token,
                httponly=True,
                secure=True,
                samesite="Strict",
                expires=expires,
                max_age=30 * 24 * 60 * 60,
            )

        return response

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/auth/logout", methods=["POST"])
def logout():
    if "user_id" in session:
        # Remove token from database and clear cookie
        token = request.cookies.get("auth_token")
        if token:
            db = get_db()
            db.execute("DELETE FROM auth_tokens WHERE token = ?", (token,))
            db.commit()

    response = jsonify({"message": "Logged out"})
    response.delete_cookie("auth_token")
    session.clear()
    return response


@app.route("/admin/users", methods=["GET"])
@admin_required
def list_users():
    db = get_db()
    users = db.execute(
        """
        SELECT id, username, is_approved, is_admin, created_at, 
               last_online,
               (SELECT COUNT(*) FROM usage_logs WHERE user_id = users.id) as activity_count
        FROM users
        ORDER BY last_online DESC
    """
    ).fetchall()
    return jsonify([dict(user) for user in users])


@app.route("/admin/users/<int:user_id>/approve", methods=["POST"])
@admin_required
def approve_user(user_id):
    db = get_db()
    db.execute("UPDATE users SET is_approved = TRUE WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({"message": "User approved"})


@app.route("/", methods=["GET"])
def index():
    # if not logged in, redirect to login
    if "user_id" not in session:
        return redirect("/login")
    return send_from_directory(".", "index.html")


@app.route("/login", methods=["GET"])
def login_html():
    return send_from_directory(".", "login.html")


@app.route("/admin", methods=["GET"])
@admin_required
def admin_html():
    return send_from_directory(".", "admin.html")


# Route song files
@login_required
@app.route("/songs/<path:path>", methods=["GET"])
def song_file(path):
    print("Sending song file", path)
    return send_from_directory("./songs", path)


# Logo.png
@app.route("/logo.png", methods=["GET"])
def logo():
    return send_from_directory("static", "logo.png")


# logo.svg
@app.route("/logo.svg", methods=["GET"])
def logo_svg():
    return send_from_directory("static", "logo.svg")


def de_search_track(search_term):

    print("Searching for", search_term)

    results = deezer.deezer_search(search_term, deezer.TYPE_TRACK)

    output = []
    for track in results:  # Assuming results is a list
        output.append(
            {
                "id": track["id"],
                "title": track["title"],
                "artist": track["artist"],
                "thumb": track["img_url"],
            }
        )

    # Prevent duplicates in trackName trackArtist
    seen = set()
    output = [
        x
        for x in output
        if not (x["title"] + x["artist"] in seen or seen.add(x["title"] + x["artist"]))
    ]

    return output


@app.route("/search", methods=["GET"])
@login_required
def search():
    search_term = request.args.get("q")
    if not search_term:
        return jsonify({"error": "Missing search term"}), 400

    results = de_search_track(search_term)

    # Log the search
    db = get_db()
    db.execute(
        "INSERT INTO usage_logs (user_id, track_id, action) VALUES (?, ?, ?)",
        (session["user_id"], search_term, "search"),
    )
    db.commit()

    return jsonify(results)


def de_add_track(track_id):

    os.makedirs("src/songs/{}".format(track_id), exist_ok=True)

    print("Processing Song", track_id)
    socketio.emit(
        "track_progress", {"track_id": track_id, "status": "starting", "progress": 0}
    )

    # Check if metadata exists
    if (
        not os.path.isfile("src/songs/{}/metadata.json".format(track_id))
        or os.path.getsize("src/songs/{}/metadata.json".format(track_id)) == 0
    ):
        print("Fetching Metadata")
        track_info = deezer.get_song_infos_from_deezer_website(
            deezer.TYPE_TRACK, track_id
        )
        metadata = {
            "title": track_info["SNG_TITLE"],
            "artist": track_info["ART_NAME"],
            "duration": track_info["DURATION"],
            "cover": track_info["ART_PICTURE"],
            "album": track_info["ALB_TITLE"],
        }
        with open("src/songs/{}/metadata.json".format(track_id), "w") as f:
            json.dump(metadata, f)

        socketio.emit(
            "track_progress",
            {"track_id": track_id, "status": "metadata_complete", "progress": 10},
        )

    # Download song from deezer if it doesnt exist yet
    if (
        not os.path.isfile("src/songs/{}/song.mp3".format(track_id))
        or os.path.getsize("src/songs/{}/song.mp3".format(track_id)) == 0
    ):
        print("Downloading Song")
        socketio.emit(
            "track_progress",
            {"track_id": track_id, "status": "downloading", "progress": 10},
        )
        track_info = deezer.get_song_infos_from_deezer_website(
            deezer.TYPE_TRACK, track_id
        )
        deezer.download_song(track_info, "src/songs/{}/song.mp3".format(track_id))
        socketio.emit(
            "track_progress",
            {"track_id": track_id, "status": "downloaded", "progress": 20},
        )

    if not os.path.isfile(
        "src/songs/{}/vocals.mp3".format(track_id)
    ) or not os.path.isfile("src/songs/{}/no_vocals.mp3".format(track_id)):

        print("Splitting Song")
        socketio.emit(
            "track_progress",
            {"track_id": track_id, "status": "splitting", "progress": 30},
        )

        output = replicate.run(
            "ryan5453/demucs:7a9db77ed93f8f4f7e233a94d8519a867fbaa9c6d16ea5b53c1394f1557f9c61",
            input={
                "jobs": 0,
                "audio": open("src/songs/{}/song.mp3".format(track_id), "rb"),
                "stem": "vocals",
                "model": "htdemucs",
                "split": True,
                "shifts": 1,
                "overlap": 0.25,
                "clip_mode": "rescale",
                "mp3_preset": 2,
                "wav_format": "int24",
                "mp3_bitrate": 320,
                "output_format": "mp3",
            },
        )

        # Save the vocals
        with open("src/songs/{}/vocals.mp3".format(track_id), "wb") as f:
            f.write(requests.get(output["vocals"]).content)

        # Save the instrumental
        with open("src/songs/{}/no_vocals.mp3".format(track_id), "wb") as f:
            f.write(requests.get(output["no_vocals"]).content)

        socketio.emit(
            "track_progress",
            {"track_id": track_id, "status": "split_complete", "progress": 50},
        )

    # exists and file is not empty
    if (
        not os.path.isfile("src/songs/{}/lyrics_raw.json".format(track_id))
        or os.path.getsize("src/songs/{}/lyrics_raw.json".format(track_id)) == 0
    ):
        print("Extracting Lyrics")
        socketio.emit(
            "track_progress",
            {"track_id": track_id, "status": "extracting_lyrics", "progress": 60},
        )

        output = replicate.run(
            "victor-upmeet/whisperx:84d2ad2d6194fe98a17d2b60bef1c7f910c46b2f6fd38996ca457afd9c8abfcb",
            input={
                "debug": False,
                "vad_onset": 0.5,
                "audio_file": open("src/songs/{}/vocals.mp3".format(track_id), "rb"),
                "batch_size": 64,
                "vad_offset": 0.363,
                "diarization": True,
                "temperature": 0,
                "align_output": True,
                "language_detection_min_prob": 0,
                "language_detection_max_tries": 5,
                "huggingface_access_token": os.getenv("HF_READ_TOKEN"),
            },
        )

        # Save the lyrics
        with open("src/songs/{}/lyrics_raw.json".format(track_id), "w") as f:
            f.write(json.dumps(output))
        # => {"segments":[{"end":30.811,"text":" The little tales they...","start":0.0},{"end":60.0,"text":" The little tales they...","start":30.811},...

        socketio.emit(
            "track_progress",
            {"track_id": track_id, "status": "lyrics_extracted", "progress": 70},
        )

    # Merge lyrics
    if (
        not os.path.isfile("src/songs/{}/lyrics_merged.json".format(track_id))
        or os.path.getsize("src/songs/{}/lyrics_merged.json".format(track_id)) == 0
    ):
        try:
            print("Merging Lyrics")
            merge_lyrics(track_id)
        except Exception as e:
            print("Error chunking lyrics", e)

            # copy lyrics_raw to lyrics.json
            with open("src/songs/{}/lyrics_raw.json".format(track_id), "r") as f:
                data = json.load(f)
            with open("src/songs/{}/lyrics.json".format(track_id), "w") as f:
                json.dump(data, f)

            socketio.emit(
                "track_progress",
                {"track_id": track_id, "status": "error", "progress": 80},
            )

        socketio.emit(
            "track_progress",
            {"track_id": track_id, "status": "lyrics_chunked", "progress": 80},
        )

    # Chunk lyrics
    if (
        not os.path.isfile("src/songs/{}/lyrics.json".format(track_id))
        or os.path.getsize("src/songs/{}/lyrics.json".format(track_id)) == 0
    ):
        try:
            print("Chunking Lyrics")
            chunk_lyrics(track_id)
        except Exception as e:
            print("Error chunking lyrics", e)

            # copy lyrics_raw to lyrics.json
            with open("src/songs/{}/lyrics_raw.json".format(track_id), "r") as f:
                data = json.load(f)
            with open("src/songs/{}/lyrics.json".format(track_id), "w") as f:
                json.dump(data, f)

            socketio.emit(
                "track_progress",
                {"track_id": track_id, "status": "error", "progress": 90},
            )

        socketio.emit(
            "track_progress",
            {"track_id": track_id, "status": "lyrics_chunked", "progress": 90},
        )

    print("Done")
    socketio.emit(
        "track_progress", {"track_id": track_id, "status": "complete", "progress": 100}
    )

    return True


@app.route("/add", methods=["GET"])
@login_required
def add():
    track_id = request.args.get("id")
    if not track_id:
        return jsonify({"error": "Missing track ID"}), 400

    # Start processing in background
    def process_track():
        try:
            de_add_track(track_id)
            socketio.emit("track_ready", {"track_id": track_id})
        except Exception as e:
            print("Error processing track", e)
            socketio.emit("track_error", {"track_id": track_id, "error": str(e)})

    # Log the download
    db = get_db()
    db.execute(
        "INSERT INTO usage_logs (user_id, track_id, action) VALUES (?, ?, ?)",
        (session["user_id"], track_id, "download"),
    )
    db.commit()

    # Start processing in a new thread
    import threading

    thread = threading.Thread(target=process_track)
    thread.start()

    return jsonify({"success": True})


# WebSocket events for progress updates
@socketio.on("connect")
def handle_connect():
    print("Client connected")


@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected")


@app.route("/auth/check", methods=["GET"])
def check_auth():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db()
    user = db.execute(
        "SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()

    return jsonify(
        {"authenticated": True, "is_admin": user["is_admin"] if user else False}
    )


@app.route("/admin/usage", methods=["GET"])
@admin_required
def get_usage_logs():
    db = get_db()

    # Get query parameters
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    action = request.args.get("action")
    username = request.args.get("username")

    # Build the query
    query = """
        SELECT u.username, l.track_id, l.action, l.created_at 
        FROM usage_logs l 
        JOIN users u ON l.user_id = u.id 
        WHERE 1=1
    """
    params = []

    if action:
        query += " AND l.action = ?"
        params.append(action)
    if username:
        query += " AND u.username LIKE ?"
        params.append(f"%{username}%")

    # Get total count
    count_query = query.replace(
        "u.username, l.track_id, l.action, l.created_at", "COUNT(*)"
    )
    total = db.execute(count_query, params).fetchone()[0]

    # Add pagination
    query += " ORDER BY l.created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])

    # Execute final query
    logs = db.execute(query, params).fetchall()

    return jsonify(
        {
            "logs": [dict(log) for log in logs],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page,
        }
    )


@app.route("/random", methods=["POST"])
@login_required
def random_song():
    try:
        data = request.get_json()
        exclude_ids = data.get("exclude_ids", [])

        # Get all processed songs (that have a metadata.json file)
        processed_songs = []
        songs_dir = "src/songs"
        for track_id in os.listdir(songs_dir):
            if os.path.isfile(os.path.join(songs_dir, track_id, "metadata.json")):
                # Skip if the track is in the exclude list
                if track_id not in exclude_ids:
                    processed_songs.append(track_id)

        if not processed_songs:
            return jsonify({"error": "No available songs"}), 404

        # Pick a random song from the available ones
        track_id = random.choice(processed_songs)

        # Get the metadata
        with open(f"src/songs/{track_id}/metadata.json", "r") as f:
            metadata = json.load(f)

        # Log the random play
        db = get_db()
        db.execute(
            "INSERT INTO usage_logs (user_id, track_id, action) VALUES (?, ?, ?)",
            (session["user_id"], track_id, "random_play"),
        )
        db.commit()

        return jsonify({"track_id": track_id, "metadata": metadata})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/stats", methods=["GET"])
@admin_required
def get_usage_stats():
    db = get_db()

    stats = {
        "total_users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_downloads": db.execute(
            "SELECT COUNT(*) FROM usage_logs WHERE action = 'download'"
        ).fetchone()[0],
        "total_searches": db.execute(
            "SELECT COUNT(*) FROM usage_logs WHERE action = 'search'"
        ).fetchone()[0],
        "total_random_plays": db.execute(
            "SELECT COUNT(*) FROM usage_logs WHERE action = 'random_play'"
        ).fetchone()[0],
        "most_active_user": db.execute(
            """
            SELECT u.username, COUNT(*) as count 
            FROM usage_logs l 
            JOIN users u ON l.user_id = u.id 
            GROUP BY u.id 
            ORDER BY count DESC 
            LIMIT 1
        """
        ).fetchone(),
    }

    if stats["most_active_user"]:
        stats["most_active_user"] = dict(stats["most_active_user"])

    return jsonify(stats)


# Add this function to update last_online
@app.before_request
def update_last_online():
    if "user_id" in session:
        db = get_db()
        db.execute(
            "UPDATE users SET last_online = CURRENT_TIMESTAMP WHERE id = ?",
            (session["user_id"],),
        )
        db.commit()


# Add this function to generate tokens
def generate_auth_token():
    return secrets.token_urlsafe(32)


def send_reset_email(email, reset_token):
    sender_email = os.getenv("SMTP_USER")
    sender_password = os.getenv("SMTP_PASSWORD")

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = email
    msg["Subject"] = "Password Reset Request"

    body = f"""
    You requested a password reset for your MelodAI account.
    Click the following link to reset your password:
    
    {os.getenv('BASE_URL')}/reset-password?token={reset_token}
    
    If you didn't request this, please ignore this email.
    """

    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(os.getenv("SMTP_HOST"), int(os.getenv("SMTP_PORT"))) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)


@app.route("/auth/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    username = data.get("username")

    db = get_db()
    user = db.execute(
        "SELECT id, email FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user or not user["email"]:
        # Don't reveal if user exists
        return jsonify({"message": "If an account exists, a reset link will be sent"})

    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    expires = datetime.now() + timedelta(hours=1)

    # Store reset token
    db.execute(
        """INSERT INTO password_resets 
           (user_id, token, expires_at) 
           VALUES (?, ?, ?)""",
        (user["id"], reset_token, expires),
    )
    db.commit()

    # Send email
    try:
        send_reset_email(user["email"], reset_token)
    except Exception as e:
        print(f"Error sending reset email: {e}")
        return jsonify({"error": "Error sending reset email"}), 500

    return jsonify({"message": "If an account exists, a reset link will be sent"})


@app.route("/auth/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    token = data.get("token")
    new_password = data.get("password")

    if not token or not new_password:
        return jsonify({"error": "Missing required fields"}), 400

    db = get_db()
    reset = db.execute(
        """SELECT user_id, expires_at FROM password_resets 
           WHERE token = ? AND used = 0""",
        (token,),
    ).fetchone()

    if (
        not reset
        or datetime.strptime(reset["expires_at"], "%Y-%m-%d %H:%M:%S.%f")
        < datetime.now()
    ):
        return jsonify({"error": "Invalid or expired reset token"}), 400

    # Update password and mark token as used
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), reset["user_id"]),
    )
    db.execute("UPDATE password_resets SET used = 1 WHERE token = ?", (token,))
    db.commit()

    return jsonify({"message": "Password reset successful"})


if __name__ == "__main__":
    socketio.run(
        app,
        host=os.getenv("HOST", "0.0.0.0"),
        port=os.getenv("PORT", 5000),
        debug=os.getenv("DEBUG", True),
        allow_unsafe_werkzeug=True,
    )
