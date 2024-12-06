# register_user.py
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import bcrypt
from mysql.connector import Error
from db_connection import get_db_connection

# Base directory for storing user data
BASE_USER_DIR = "user_data"

def create_user_directory(username):
    """Creates a directory for the user if it does not exist."""
    user_dir = os.path.join(BASE_USER_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    print(f"Directory created for user: {user_dir}")

def register_user(username: str, password: str):
    # Hash the password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert the new user with the hashed password
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            (username, password_hash)
        )
        conn.commit()
        print(f"User {username} registered successfully.")

        # Create a directory for the user after successful registration
        create_user_directory(username)

    except Error as e:
        if e.errno == 1062:  # Duplicate entry error code for MySQL
            print("Username already exists.")
        else:
            print("An error occurred:", e)

    finally:
        # Close the cursor and connection
        cursor.close()
        conn.close()

# Testing the registration function
if __name__ == "__main__":
    # Ensure the base directory exists
    os.makedirs(BASE_USER_DIR, exist_ok=True)

    username = input("Enter a username: ")
    password = input("Enter a password: ")
    register_user(username, password)