""" Example showing how to authenticate as an application without a user.

This flow is suitable for web services which require access to Veracity services
but do not operate on user data.
"""

from veracity_platform.identity import ClientSecretCredential

CLIENT_ID = "<YOUR_APPLICATION_CLIENT_ID>"
CLIENT_SECRET = "<YOUR_APPLICATION_CLIENT_SECRET>"

cred = ClientSecretCredential(CLIENT_ID, client_secret=CLIENT_SECRET)
token = cred.get_token(scopes=['veracity_data'])
print(token)
