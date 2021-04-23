""" Example showing how a user authenticates with Veracity locally with their webbrowser.

This flow is suitable for native applications running on the user's own computer.

Notes:
    For native apps, you must use the http://localhost redirect URI.  This must be
    specified in the Veracity developer portal exactly as used here.

"""

import os
from veracity_platform.identity import InteractiveBrowserCredential

CLIENT_ID = os.environ.get("EXAMPLE_VERACITY_CLIENT_ID")
# TODO: Secret should not be necessary for user-auth flow, but Veracity IDP doesn't work without it.
CLIENT_SECRET = os.environ.get("EXAMPLE_VERACITY_CLIENT_SECRET")
SUBSCRIPTION_KEY = os.environ.get("EXAMPLE_VERACITY_SUBSCRIPTION_KEY")
REDIRECT_URI = "http://localhost/login"

cred = InteractiveBrowserCredential(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
token = cred.get_token(scopes=['veracity_service'], timeout=30)
print(f'Service API token:\n{token}\n\n')
assert 'access_token' in token

# TODO: This does not work.
# According to the Veracity documentation, this should provide an access token
# for the data fabric API.  However, I cannot get this to work with my client
# application.
# Ref: https://developer.veracity.com/docs/section/identity/authentication/web-native#authenticating-a-user
token = cred.get_token(scopes=['veracity_datafabric'], timeout=30)
print(f'Data Fabric API token:\n{token}\n\n')
assert 'access_token' in token
