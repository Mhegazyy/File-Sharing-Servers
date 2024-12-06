# db_connection.py
import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",           # Use your MySQL user
        password="root",    # MySQL password for app_user
        database="encrypted_file_storage"
    )
