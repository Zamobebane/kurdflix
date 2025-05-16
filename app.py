import streamlit as st
import sqlite3
import hashlib
import stripe
import boto3

# ─── CONFIG ────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="Kurdflix", layout="wide")

stripe.api_key = st.secrets["STRIPE_SECRET_KEY"]
S3_BUCKET        = st.secrets["S3_BUCKET"]
PRICE_ID         = st.secrets["STRIPE_PRICE_ID"]
SUCCESS_URL      = st.secrets["SUCCESS_URL"]   # e.g. "https://your-app.streamlitapp.com/?session_id={CHECKOUT_SESSION_ID}"
CANCEL_URL       = st.secrets["CANCEL_URL"]

AWS_KEY_ID       = st.secrets["AWS_ACCESS_KEY_ID"]
AWS_SECRET_KEY   = st.secrets["AWS_SECRET_ACCESS_KEY"]

# ─── DATABASE SETUP ───────────────────────────────────────────────────────────
conn = sqlite3.connect("kurdflix.db", check_same_thread=False)
c    = conn.cursor()
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    name     TEXT,
    password TEXT,
    paid     INTEGER DEFAULT 0
)
""")
conn.commit()

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def verify_password(pw: str, hashed: str) -> bool:
    return hash_password(pw) == hashed

def get_user(username: str):
    c.execute("SELECT username, name, password, paid FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row: return None
    return {"username": row[0], "name": row[1], "password": row[2], "paid": bool(row[3])}

def add_user(username: str, name: str, pw_hashed: str):
    c.execute("INSERT INTO users (username, name, password) VALUES (?, ?, ?)",
              (username, name, pw_hashed))
    conn.commit()

def mark_paid(username: str):
    c.execute("UPDATE users SET paid = 1 WHERE username = ?", (username,))
    conn.commit()

def list_movies():
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_KEY
    )
    resp = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix="videos/")
    if "Contents" not in resp: return []
    return [
        obj["Key"].rsplit("/", 1)[-1]
        for obj in resp["Contents"]
        if obj["Key"].endswith(".mp4")
    ]

# ─── HANDLE PAYMENT CALLBACK ──────────────────────────────────────────────────
params     = st.experimental_get_query_params()
session_id = params.get("session_id", [None])[0]

if session_id and not st.session_state.get("payment_processed"):
    session = stripe.checkout.Session.retrieve(session_id)
    if session.payment_status == "paid":
        mark_paid(session.client_reference_id)
        st.session_state.payment_processed = True
        st.experimental_rerun()

# ─── AUTHENTICATION UI ────────────────────────────────────────────────────────
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    choice = st.sidebar.selectbox("Account", ["Login", "Register"])
    if choice == "Login":
        u = st.sidebar.text_input("Username")
        p = st.sidebar.text_input("Password", type="password")
        if st.sidebar.button("Login"):
            user = get_user(u)
            if user and verify_password(p, user["password"]):
                st.session_state.logged_in = True
                st.session_state.user      = user
                st.experimental_rerun()
            else:
                st.sidebar.error("Invalid username or password")
    else:  # Register
        n = st.sidebar.text_input("Name")
        u = st.sidebar.text_input("Username")
        p = st.sidebar.text_input("Password", type="password")
        if st.sidebar.button("Register"):
            if get_user(u):
                st.sidebar.error("That username is taken")
            else:
                add_user(u, n, hash_password(p))
                st.sidebar.success("Registered! Please switch to Login.")
    st.stop()

# ─── MAIN APP ─────────────────────────────────────────────────────────────────
user = st.session_state.user
st.sidebar.write(f"👋 Welcome, **{user['name']}**")

if not user["paid"]:
    st.warning("🛑 Your \$5/month membership is inactive.")
    if st.button("Subscribe for \$5/month"):
        checkout = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=SUCCESS_URL,
            cancel_url=CANCEL_URL,
            client_reference_id=user["username"]
        )
        st.markdown(f"[Proceed to payment →]({checkout.url})")
    st.stop()

st.title("📺 Browse & Play Kurdish Films on Kurdflix")

movies = list_movies()
if not movies:
    st.info("No videos found in your bucket yet.")
else:
    choice = st.selectbox("Select a movie", movies)
    if st.button("Play"):
        s3 = boto3.client(
            "s3",
            aws_access_key_id=AWS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_KEY
        )
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": f"videos/{choice}"},
            ExpiresIn=3600
        )
        st.video(url)
