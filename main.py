#!/usr/bin/env python3
# coding: utf-8
import hashlib
import requests
from progressbar import ProgressBar
from getpass import getpass
from lastpass import Vault
from lastpass.exceptions import (
        LastPassIncorrectGoogleAuthenticatorCodeError,
        LastPassIncorrectYubikeyPasswordError,
        LastPassUnknownError
)

DEVICE_ID = 'lastpass-hibp'

username = 'username'
password = 'password'

def check_password(password):
    if isinstance(password, str):
        password = password.encode()

    h = hashlib.sha1(password).hexdigest().upper()
    pre = h[:5]
    suffix = h[5:]
    response = requests.get('https://api.pwnedpasswords.com/range/{}'.format(pre))
    response = response.content.decode()
    hashes = [x.split(':')[0].strip()
              for x in response.split("\r\n")]
    return suffix in hashes

try:
    vault = Vault.open_remote(username, password, None, DEVICE_ID)
except LastPassIncorrectGoogleAuthenticatorCodeError as _:
    multifactor_password = getpass('Enter MFA code: ')
    vault = Vault.open_remote(username, password, multifactor_password, DEVICE_ID)
except LastPassIncorrectYubikeyPasswordError as _:
    multifactor_password = getpass('Enter Yubikey password: ')
    vault = Vault.open_remote(username, password, multifactor_password, DEVICE_ID)
except LastPassUnknownError as e:
    if 'Multifactor authentication required' in str(e):
        multifactor_password = getpass('Enter MFA code: ')
        vault = Vault.open_remote(username, password, multifactor_password, DEVICE_ID)
    else:
        raise e

number_of_accounts = len(vault.accounts)
with open('account-list', 'w') as f:
    with ProgressBar(max_value=number_of_accounts) as bar:
        i = 0
        for account in vault.accounts:
            flag = 'leaked' if check_password(account.password) else ''
            f.write("[{:6s}] <{:s}> {:s} @ {:s}\n".format(
                flag,
                account.id.decode(),
                account.username.decode(),
                account.name.decode()))
            i += 1
            bar.update(i)
