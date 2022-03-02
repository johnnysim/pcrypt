import hashlib
from flask_bcrypt import Bcrypt


class Pcrypt(Bcrypt):
    """
    Pcrypt extends the flask_bcrypt.Bcrypt class by adding pepper functionality to it.

    Params:
        app (object): Flask app object passed to Bcrypt
        pepper (str): pepper secret key, should be store on server.

    Example::

        app = Flask(__name__)
        pepper = "thisismypeppersecret"
        pcrypt = Pcrypt(app, pepper)

    To hash the password::

        password = "abc1111"
        hashed_password = pcrypt.hash_password(password)

    To compare and check password hash::

        result = pcrypt.compare_password(hashed_password, password)
    """

    def __init__(self, app, pepper) -> None:
        super().__init__(app)
        self.pepper = pepper

    def _add_pepper(self, password):
        peppered_pw = password + self.pepper
        sha256_pw = hashlib.sha256(peppered_pw.encode()).hexdigest()
        return sha256_pw

    def hash_password(self, password, salt_rounds=12):
        sha256_pw = self._add_pepper(password)
        hashed_pw = self.generate_password_hash(sha256_pw, salt_rounds).decode()
        return hashed_pw

    def compare_password(self, hashed_password, password):
        """
        Params:
            password (str): the plain password from user.
            hashed_password (str): the hashed password stored in database.
        Returns:
            Boolean
        """
        sha256_pw = self._add_pepper(password)
        return self.check_password_hash(hashed_password, sha256_pw)
