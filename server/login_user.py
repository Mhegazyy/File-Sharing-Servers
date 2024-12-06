import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import bcrypt
from mysql.connector import Error
from db_connection import get_db_connection

def login_user(username: str, password: str):
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Retrieve the hashed password and privilege level for the provided username
        cursor.execute("SELECT password_hash, privilege FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result:
            stored_password_hash, privilege = result
            # Check if the provided password matches the stored hash
            if bcrypt.checkpw(password.encode(), stored_password_hash.encode()):
                print("Login successful!")
                return True, privilege  # Return privilege level along with success status
            else:
                print("Username or password incorrect.")
                return False, None
        else:
            print("Username or password incorrect.")
            return False, None

    except Error as e:
        print("An error occurred:", e)
        return False, None

    finally:
        # Close the cursor and connection
        cursor.close()
        conn.close()
        
# Testing the login function
if __name__ == "__main__":
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    login_user(username, password)