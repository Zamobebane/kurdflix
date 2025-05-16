import streamlit as st
import streamlit_authenticator as stauth
import stripe
import boto3
from your_db_module import get_user, add_user

# —–– CONFIG —––
st.set_page_config(page_title="Kurdflix", layout="wide")

# Load secrets from GitHub Actions or Streamlit Cloud secrets
stripe.api_key = st.secrets["STRIPE_SECRET_KEY"]
S3_BUCKET = st.secrets["S3_BUCKET"]
AUTH_CONFIG = st.secrets["AUTH_CONFIG"]

# —–– AUTHENTICATION —––
authenticator = stauth.Authenticate(
    AUTH_CONFIG["credentials"],
    AUTH_CONFIG["cookie"]["name"],
    AUTH_CONFIG["cookie"]["key"],
    AUTH_CONFIG["cookie"]["expiry_days"],
)
name, authentication_status, username = authenticator.login("Login", "main")

if authentication_status:
    st.sidebar.write(f"Welcome, {name}!")
    # Check payment status in your DB:
    if not get_user(username)["paid"]:
        st.warning("🛑 Your \$5/month membership is inactive.")
        if st.button("Subscribe for \$5/month"):
            # Create Stripe Checkout session
            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[{"price": st.secrets["STRIPE_PRICE_ID"], "quantity": 1}],
                mode="subscription",
                success_url=st.secrets["SUCCESS_URL"],
                cancel_url=st.secrets["CANCEL_URL"],
                client_reference_id=username
            )
            st.markdown(f"[Proceed to payment →]({session.url})")
        st.stop()
    # Show library after paid
    st.title("📺 Browse Movies")
    # Fetch movie list from DB
    movies = your_db_module.list_movies()
    choice = st.selectbox("Select a movie", movies)
    if st.button("Play"):
        s3 = boto3.client("s3")
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": f"videos/{choice}.mp4"},
            ExpiresIn=3600
        )
        st.video(url)
elif authentication_status == False:
    st.error("Username/password is incorrect")
else:
    st.info("Please log in")

authenticator.register_user("Register", preauthorization=False)
