import requests
import hashlib


def req_api_data(query_char):
    url = f'https://api.pwnedpasswords.com/range/{query_char}' 
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error Fetching: {res.status_code}, check the api and try again.')
    return res


def get_password_leaks_count(hashes, hash_to_check ):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h in hashes:
        print(h)


def pwned_api_check(password):
    """Check password if its exists in the API response"""
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = req_api_data(first5_char)
    print(first5_char, tail)
    return get_password_leaks_count(response, tail)


pwned_api_check('123')
