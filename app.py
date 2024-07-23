import streamlit as st
import pickle
import hashlib
import sqlite3

# Load ML models (same as before)
vector = pickle.load(open("vector.pkl", 'rb'))
model = pickle.load(open("final.pkl", 'rb'))

# Define database functions
def create_connection():
    conn = sqlite3.connect('user_data.db')
    return conn

def create_table(conn):
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (username TEXT PRIMARY KEY, password TEXT)''')
    conn.commit()

def add_user(conn, username, password):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()

def check_user(conn, username, password):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    return cursor.fetchone() is not None

# Define page functions
def home():
    st.write("""
    # Welcome to the Fake News Detector App!
    
Project Overview:

Welcome to our project on Fake News Detection using Machine Learning! In today's digital world, the spread of misinformation has become a critical issue.
Our project aims to combat this by developing a sophisticated system that can accurately identify and classify news articles as real or fake using advanced 
machine learning algorithms.


Purpose and Importance:

The rapid dissemination of fake news can lead to widespread misinformation,
panic, and mistrust in reliable news sources. Our project addresses this challenge by
leveraging machine learning to provide a reliable and scalable solution for detecting 
fake news. This tool not only helps individuals verify the authenticity of news articles 
but also contributes to a more informed and discerning society.


Key Features

Accurate Detection:- Utilizing state-of-the-art machine learning models to classify news articles with high accuracy.

User-Friendly Interface:- An easy-to-use web application that allows users to input news articles and receive immediate detection results.

Real-Time Analysis:- Provides instant feedback on the authenticity of news articles, helping users make informed decisions quickly.
Comprehensive Evaluation:- Detailed metrics and performance reports to ensure the reliability of our detection system.


User Guidance:

To use our fake news detection tool:

Input News Article:- Paste the text of the news article you want to verify into the provided input field.

Get Results:- Click the 'Predict' button to receive an instant analysis of the article, indicating whether it is real or fake.

Explore More:- Learn about the methodology behind our project, explore the detailed results, and understand the impact of machine learning in combating fake news.


    ---
    """)

def register():
    st.title("Register User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        conn = create_connection()
        # Check if the username already exists
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            st.warning("Username already exists. Please choose a different username.")
        elif password == confirm_password:
            add_user(conn, username, hashlib.sha256(password.encode('utf-8')).hexdigest())
            st.success("Registration Successful!")
            st.sidebar.selectbox("Select an option", ["Home", "Login"])  # Update sidebar options
        else:
            st.warning("Passwords do not match!")


def login():
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        conn = create_connection()
        hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if check_user(conn, username, hashed_pw):
            st.session_state['logged_in'] = True  # Flag user as logged in
            st.success(f"Welcome back, {username}!")
            st.sidebar.selectbox("Select an option", ["Home", "Prediction"])  # Update sidebar options
        else:
            st.warning("Incorrect username or password.")


def predict_news(news):
    predict = model.predict(vector.transform([news]))[0]
    return predict

def prediction():
    st.title("Fake News Prediction App")

    # Rest of the prediction logic (same as before)
    st.header("Enter the text of the news article below")
    news = st.text_area("News Text")

    if st.button("Predict"):
        if news:
            prediction = predict_news(news)
            st.success("News headline is -> {}".format(prediction))
        else:
            st.warning("Please enter the text of the news article to make a prediction.")

def main():
    # Authentication flow
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
    logged_in = st.session_state['logged_in']

    if not logged_in:
        login_choice = st.sidebar.selectbox("Login or Register", ["Login", "Register"])
        if login_choice == "Login":
            login()
        else:
            register()
    else:
        st.sidebar.title("Navigation")
        menu = ["Home", "Prediction"]
        choice = st.sidebar.selectbox("Select an option", menu)
        if choice == "Home":
            home()
        elif choice == "Prediction":
            prediction()
        # Optionally add a logout button

if __name__ == '__main__':
    conn = create_connection()
    create_table(conn)
    main()
