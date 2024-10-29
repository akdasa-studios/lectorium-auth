import pycouchdb
import hashlib
import binascii

def get_user_data(
    server_url,
    username,
):
    server = pycouchdb.Server(server_url)
    users_db = server.database('_users')
    user_id = f"org.couchdb.user:{username}"

    try:
        user_data = users_db.get(user_id)
        return user_data
    except pycouchdb.exceptions.NotFound:
        print("User not found.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


# based on https://github.com/perfood/couch-pwd/blob/master/index.js
def get_password_hash(
    pwd: str,
    salt: str,
    iterations=10,
    keylen=20,
    digest='SHA1'
) -> str:
    if not pwd:
        raise ValueError('password missing')
    if not salt:
        raise ValueError('salt missing')

    hash_bytes = hashlib.pbkdf2_hmac(
        digest.lower(),
        pwd.encode(),
        salt.encode(),
        iterations,
        keylen
    )
    return binascii.hexlify(hash_bytes).decode()
