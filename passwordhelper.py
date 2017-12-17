import hashlib
# import os
# import base64

from base64 import b64encode
from os import urandom


class PasswordHelper:

	def get_hash(self, plain):
		# hashlib.sha256(str(random.getrandbits(256)).encode('utf-8')).hexdigest()
		return hashlib.sha512(plain.encode('utf-8')).hexdigest()

	def get_salt(self):
		# return base64.b64decode(os.urandom(20))
		random_bytes = urandom(64)
		token = b64encode(random_bytes).decode('utf-8')
		return token

	def validate_password(self, plain, salt, expected):
		return self.get_hash(plain + salt) == expected