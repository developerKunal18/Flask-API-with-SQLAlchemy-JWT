from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
import bcrypt

app = Flask(__name__)

# ---------- Config ----------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

SECRET_KEY = "supersecretkey"

db = SQLAlchemy(app)

# ---------- Model ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)

# Create DB
with app.app_context():
    db.create_all()

# ---------- Register ----------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    hashed = bcrypt.hashpw(
        data["password"].encode(),
        bcrypt.gensalt()
    )

    user = User(
        username=data["username"],
        password=hashed
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered"})

# ---------- Login ----------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    user = User.query.filter_by(
        username=data["username"]
    ).first()

    if user and bcrypt.checkpw(
        data["password"].encode(),
        user.password
    ):
        token = jwt.encode(
            {
                "username": user.username,
                "exp": datetime.datetime.utcnow()
                + datetime.timedelta(hours=1)
            },
            SECRET_KEY,
            algorithm="HS256"
        )

        return jsonify({"token": token})

    return jsonify({
        "message": "Invalid credentials"
    }), 401

# ---------- Protected Route ----------
@app.route("/profile")
def profile():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({
            "message": "Token missing"
        }), 401

    try:
        decoded = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        return jsonify({
            "message": f"Welcome {decoded['username']}"
        })

    except:
        return jsonify({
            "message": "Invalid token"
        }), 401

# ---------- Run ----------
if __name__ == "__main__":
    app.run(debug=True)
