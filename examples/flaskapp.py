""" Demo Flask web app using the Veracity identity service.

This example retrieves a user token using auth-code-flow.  Both parts of the flow
are handled by the /login endpoint.  Note, the app's Reply URL must be set in
the developer portal exactly so in order for Veracity to return a token:

    - http://localhost/login           - when running the app locally.
    - https://<your_host_name>/login   - when deployed online.

Requirements:

    1. Before running, install Flask:

      $ pip install flask flask-session

"""

from flask import Flask, request, redirect, session, url_for
# from flask_session import Session
from veracity_platform.identity import IdentityService

app = Flask(__name__)
app.secret_key = 'mytopsecretkey'  # Used by Flask to secure the session data.

# Initialize server-side session (necessary if the session cookie exceeds 4 KB).
# TODO:  Filesystem session won't work on Azure most likely.
# app.config['SESSION_TYPE'] = 'filesystem'
# sesh = Session(app)

# Parameters from veracity app on developer portal.  Caution! The redirect URI must
# be *exactly* the same as a "Reply URL" in the developer portal, including the port number!
# Veracity  will reject auth requests if the redirect URI does not match a specified reply URL.
CLIENT_ID = "<YOUR_APPLICATION_CLIENT_ID>"
CLIENT_SECRET = "<YOUR_APPLICATION_CLIENT_SECRET>"
SUBSCRIPTION_KEY = "<YOUR_API_SUBSCRIPTION_KEY>"
REDIRECT_URI = "http://localhost/login"
SCOPES = ['veracity_service']

id_service = IdentityService(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)


@app.route('/', methods=['get'])
def index():
    """ Will start authentication flow by redirecting to Veracity IDP.
    """
    if not validate_user(session):
        print("Not logged in")
        return redirect(url_for('login'))

    profile = get_user_profile(session)
    return profile


@app.route('/login', methods=['get', 'post'])
def login():
    """ Handle user authentication using auth code flow.

    If 'code' is in the query parameters, attempts to acquire a token using
    auth code flow.  If that fails or there is no auth code, then redirects
    to the Veracity login page.  The Veracity login process will redirect back
    to this route (see REDIRECT_URI) with the auth 'code' as a query parameter.
    """
    if 'code' in request.args:
        flow = session.pop('flow', {})
        result = id_service.acquire_token_by_auth_code_flow(flow, request.args)
        print(result)
        if "error" not in result:
            result.pop("scope", None)  # Don't need this in the session
            result.pop("auth_code", None)
            session['token'] = result
            return redirect(url_for('index'))

    # No auth code or token acquisition failed.  Redirect to Veracity login.
    session['flow'] = id_service.initiate_auth_code_flow(SCOPES, redirect_uri=REDIRECT_URI)
    return redirect(session['flow']['auth_uri'])


def validate_user(session):
    try:
        token = session.get('token', {})
        id_token = token.get('id_token')
        jwt_content = id_service.validate_token(id_token)
        session['username'] = jwt_content.get('name')
    except Exception as err:
        print(err)
        return False
    print('User token is valid.')
    return True


def get_user_profile(session):
    """ Queries user profile from Veracity service API.
    """
    import requests
    token = session.get("token", {})
    access_token = token.get("access_token", "")
    url = "https://api.veracity.com/veracity/services/v3/my/profile"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Ocp-Apim-Subscription-Key": SUBSCRIPTION_KEY,
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return "Failed to get profile!"


if __name__ == '__main__':
    # Ensure port is set exactly as REDIRECT_URI!  Default is 80 for HTTP if no port in REDIRECT_URI.
    app.run(debug=True, port=80)
