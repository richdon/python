import datetime
import os
import jwt

from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

# config
server.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
server.config["MYSQL_USER"] = os.environ.get("MYSQL_USER")
server.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")
server.config["MYSQL_DB"] = os.environ.get("MYSQL_DB")
server.config["MYSQL_PORT"] = os.environ.get("MYSQL_PORT")


@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "missing credentials", 401
    
    # check db for username and password
    cur = mysql.connection.cursor()
    res = cur.execute(
        f"SELECT email, password FROM user WHERE email={(auth.username,)}"
    )
    if len(res) > 0:
        user_row = cur.fetchone()
        email, password = user_row

        if auth.username != email or auth.password != password:
            return "invalid credentials", 401
        return create_jwt(auth.username, os.environ.get("JWT_SECRET"), True)

    return "invalid credentials", 401


@server.route("/validate", method=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]
    if not encoded_jwt:
        return "missing credentials", 401

    encoded_jwt = encoded_jwt.split()[1]
    try:
        decoded = jwt.decode(encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"])
    except:
        return "not authorized", 403
    return decoded, 200


def create_jwt(username, secret, authz):
    return jwt.encode(
        {"username": username, "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1),
         "iat": datetime.datetime.now(), "admin": authz}, secret, algorithm="HS256"
    )


if __name__ == "__main__":
    server.run(port=5000, host="0.0.0.0")
