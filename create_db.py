import pymysql
from sqlalchemy.engine.url import make_url
import os

# Load database URL from environment or .env
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:Root%40123@localhost:3306/login_demo")
url = make_url(DATABASE_URL)

# Extract connection info without database
connection_config = {
    "host": url.host,
    "user": url.username,
    "password": url.password,
    "port": url.port or 3306,
    # Do not specify db here
}

def create_database_if_not_exists(db_name):
    conn = pymysql.connect(**connection_config)
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`;")
        conn.commit()
    finally:
        conn.close()

if __name__ == "__main__":
    create_database_if_not_exists(url.database)
    print(f"Database '{url.database}' ensured to exist.")
