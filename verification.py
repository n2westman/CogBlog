import re
import random
import string
import hashlib
import hmac

"""
This File Contains verification info, including but not limited to regular expression usage, string validation, and hashing.

"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


#Salts and Hashes the String.
def hash_str(s):
    return hmac.new('Secret',s).hexdigest()

#Makes a cookie according to our hashing algorithm.
def make_cookie(s):
    return '%s|%s' % (s,hash_str(s));

#Returns True if the hash is correct.
def verify_cookie(s):
    t = s.split('|')
    return hash_str(t[0]) == t[1]

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    s = h.split("|")[1]
    return make_pw_hash(name, pw, s) == h
