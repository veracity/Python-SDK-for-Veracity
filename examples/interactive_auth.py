""" Example showing how a user authenticates with Veracity locally with their webbrowser.

This flow is suitable for native applications running on the user's own computer.

Notes:
    For native apps, you must use the http://localhost redirect URI.  This must be
    specified in the Veracity developer portal exactly as used here.

"""

from veracity_platform.identity import InteractiveBrowserCredential


CLIENT_ID = "<YOUR_APPLICATION_CLIENT_ID>"
# TODO: Secret should not be necessary for user-auth flow, but Veracity IDP doesn't work without it.
CLIENT_SECRET = "<YOUR_APPLICATION_CLIENT_SECRET>"
REDIRECT_URI = "http://localhost/login"

# service = IdentityService(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
cred = InteractiveBrowserCredential(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
token = cred.get_token(scopes=['veracity_service'], timeout=30)
print(token)
