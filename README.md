# Pcrypt

Pcrypt extends the flask_bcrypt.Bcrypt class by adding pepper functionality to it.

Dependencies:

- flask-bcrypt: https://github.com/maxcountryman/flask-bcrypt

  pip install flask-bcrypt

Example:

    app = Flask(__name__)
    pepper = "thisismypeppersecret"
    pcrypt = Pcrypt(app, pepper)

To hash the password:

    password = "abc1111"
    hashed_password = pcrypt.hash_password(password)

To compare and check password hash:

    result = pcrypt.compare_password(hashed_password, password)
