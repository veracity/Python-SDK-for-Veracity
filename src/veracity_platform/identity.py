""" Veracity Identity API

It is not possible to use the Microsoft authentication library (msal) or the Azure
identity package (azure.identity) to authenticate with Veracity because they do not
direct to the correct login page.  This is because they lack the policy query parameter.
Instead, this package constructs wraps the lower-level msal.oauth2cli.oidc classes to
correctly authenticate against Veracity.

The classes in this module are designed as drop-in replacements for the msal.ClientApplication
and azure.identity.*Credential classes.

Notes:
    - Microsoft have a work-in-progress code for B2C authorization on GitHub:
      https://github.com/Azure-Samples/ms-identity-python-samples-common.  However,
      this is not yet production-ready.

References:
    - https://developer.veracity.com/services/identity
    - https://developer.veracity.com/docs/section/identity/identity
    - https://docs.microsoft.com/en-us/python/api/msal/msal.application.clientapplication
    - https://github.com/AzureAD/microsoft-authentication-library-for-python
    - https://github.com/veracity/Python-Sample-to-Connect-to-Veracity-Service
    - https://github.com/Azure-Samples/ms-identity-python-webapp
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Sequence
from msal.oauth2cli import oidc


MICROSOFT_AUTHORITY_HOSTNAME = "https://login.microsoftonline.com"
VERACITY_AUTHORITY_HOSTNAME = "https://login.veracity.com"

DEFAULT_TENANT_ID = "dnvglb2cprod.onmicrosoft.com"
DEFAULT_REPLY_URL = "http://localhost"
DEFAULT_POLICY = "b2c_1a_signinwithadfsidp"

# Veracity scopes require suffixes before use:
#    "/.default" for web app, user not present scenario.  For example:
#       https://dnvglb2cprod.onmicrosoft.com/83054ebf-1d7b-43f5-82ad-b2bde84d7b75/.default
#    "/user_impersonation" for client application, user present scenario.  For example:
#       'https://dnvglb2cprod.onmicrosoft.com/83054ebf-1d7b-43f5-82ad-b2bde84d7b75/user_impersonation
ALLOWED_SCOPES = {
    'veracity_service': 'https://dnvglb2cprod.onmicrosoft.com/83054ebf-1d7b-43f5-82ad-b2bde84d7b75',
    'veracity_datafabric': 'https://dnvglb2cprod.onmicrosoft.com/37c59c8d-cd9d-4cd5-b05a-e67f1650ee14',
    # data is alias for datafabric.
    'veracity_data': 'https://dnvglb2cprod.onmicrosoft.com/37c59c8d-cd9d-4cd5-b05a-e67f1650ee14',
    'veracity_iot': 'https://dnvglb2cprod.onmicrosoft.com/29a8760a-d13a-41ce-998e-0a00c3d948d5',
}


def expand_veracity_scopes(scopes: Sequence[str], user_present: bool = False) -> Sequence[str]:
    """ Replaces Veracity short-hand scopes for actual scopes, scenario dependent.

    See :const:`ALLOWED_SCOPES` for list of short-hand scopes.

    The actual scope depends on the scenario (user present or user not present),
    By default it works for the user not present scenario.

    Args:
        scopes (list): List of scopes, which may include Veracity shorthand scopes.
        user_present (bool): Set True for user-present, i.e. interactive, scenarios.

    Returns:
        A list of scopes with the Veracity scopes replaced with the correct
        scope for this required scenario.
    """
    if scopes is None:
        return None

    if user_present:
        suffix = '/user_impersonation'
    else:
        suffix = '/.default'

    return [
        ALLOWED_SCOPES[s] + suffix
        if s in ALLOWED_SCOPES else s
        for s in scopes
    ]


class IdentityError(Exception):
    pass


class Authority(object):
    """ Represents the Veracity authority from which to get tokens.
    """
    def __init__(self, tenant=DEFAULT_TENANT_ID, policy=DEFAULT_POLICY, api_version='v2.0'):
        self.tenant = tenant
        self.policy = policy
        self.api_version = api_version
        self.metadata = self.reload_metadata()

    @property
    def url(self):
        from datetime import date
        DEADLINE = date.fromisoformat('2021-07-01')
        if date.today() >= DEADLINE:
            # After 15 March use this as MS deprecating their login URL.
            return f"https://login.veracity.com/{self.tenant}"
        else:
            return f"https://login.microsoftonline.com/{self.tenant}"

    @property
    def safe_policy(self):
        import urllib.parse
        return urllib.parse.quote(self.policy)

    @property
    def metadata_url(self):
        if self.api_version in [1, 1.0, 'v1', 'v1.0']:
            return f"{self.url}/.well-known/openid-configuration/"
        else:
            # Assume is like v2.0; will break otherwise.
            return f"{self.url}/{self.api_version}/.well-known/openid-configuration/"

    @property
    def authorize_endpoint(self):
        return self.metadata.get('authorization_endpoint')

    def token_endpoint(self):
        return self.metadata.get('token_endpoint')

    @property
    def jwtk_endpoint(self):
        return self.metadata.get('jwks_uri')

    @property
    def issuer_endpoint(self):
        return self.metadata.get('issuer')

    @property
    def jwtk_url(self):
        return f"{self.jwtk_endpoint}?p={self.safe_policy}"

    def reload_metadata(self):
        import requests
        resp = requests.get(self.metadata_url)
        if resp.status_code == 200:
            self.metadata = resp.json()
            # Fix openid token validation.
            if not self.metadata['issuer'].endswith('/'):
                self.metadata['issuer'] = self.metadata['issuer'] + '/'
            return self.metadata
        else:
            raise IdentityError(f"HTTP/{resp.status_code} Failed to get metadata.")

    def authorize_url(self, **params):
        params['p'] = self.policy
        safe_params = self._make_param_string(**params)
        return '?'.join([self.authorize_endpoint, safe_params])

    def token_url(self, **params):
        params['p'] = self.policy
        safe_params = self._make_param_string(**params)
        return '?'.join([self.token_endpoint, safe_params])

    def client_token_url(self, **params):
        safe_params = self._make_param_string(**params)
        return '?'.join([self.token_endpoint, safe_params])

    def _make_param_string(self, **params):
        from urllib.parse import urlencode, quote
        return urlencode(params, quote_via=quote)


class IdentityService(object):
    """ Provides Veracity identity services for users and applications.
    This class is designed as a drop-in replacement for msal.ConfidentialClientApplication
    objects.

    Args:
        client_id (str): Client application ID.
        redirect_uri (str): Redirect URI for interactive flows.  Not required
            for service principal flows without user interaction. Whatever URI you
            choose here, it MUST be specified in the Veracity Developer Portal as
            your app's Reply URL.
        client_secret (str): Optional client secret.
        authority (Authority): If different from Veracity authority.  You should
            not change this - by default the service will connect to the
            Veracity authority automatically.
    """
    def __init__(self, client_id, redirect_uri=None, client_secret=None, authority=None):
        self.authority = authority or Authority()
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._openid_client = None
        self.token_cache = {}

    @property
    def openid_client(self):
        if self._openid_client is None:
            self._openid_client = oidc.Client(
                server_configuration=self.authority.metadata,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
        return self._openid_client

    # #########################################################################
    # Overrides for msal.ClientApplication
    # #########################################################################

    def acquire_token_by_auth_code_flow(self, flow, auth_response, scopes=None, **kwargs):
        """ Validates and acquires token from auth code flow.
        Drop-in replacement for msal.ClientApplication method.

        Auth code flow is a "user present" scenario.

        References:
            - https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
        """
        if "code" not in auth_response:
            raise IdentityError("Authentication server did not send an authorization code.")

        if "state" not in auth_response:
            raise IdentityError("Authentication response does not include OAuth state.")

        if auth_response["state"] != flow["state"]:
            raise IdentityError("Authentication response OAuth state does not match the request.")

        user_present = kwargs.pop('user_present', True)

        # Inject policy into query parameters.
        # This is the step where Veracity deviates from msal and azure.identity!
        params = kwargs.setdefault('params', {})
        params['p'] = self.authority.policy

        return self.openid_client.obtain_token_by_auth_code_flow(
            flow,
            auth_response,
            scope=expand_veracity_scopes(scopes, user_present=user_present),
            **kwargs,
        )

    def acquire_token_by_authorization_code(self, code, scopes, **kwargs):
        """ Acquires a token using the requests library.
        Drop-in replacement for msal.ClientApplication method.

        References:
            - https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
        """
        user_present = kwargs.pop('user_present', False)
        expanded_scopes = expand_veracity_scopes(scopes, user_present=user_present)
        return self.openid_client.obtain_token_by_authorization_code(
            code, redirect_uri=self.redirect_uri, scope=expanded_scopes, **kwargs)

    def acquire_token_by_refresh_token(self, refresh_token, scopes, **kwargs):
        user_present = kwargs.pop('user_present', False)
        expanded_scopes = expand_veracity_scopes(scopes, user_present=user_present)
        token = self.openid_client.obtain_token_by_refresh_token(refresh_token, scope=expanded_scopes, **kwargs)
        self._save_token(token)
        return token

    def acquire_token_silent(self, scopes, account, force_refresh=False, **kwargs):
        raise NotImplementedError()

    def acquire_token_silent_with_error(self, scopes, account, force_refresh=False, **kwargs):
        raise NotImplementedError()

    def get_accounts(self, username=None):
        raise NotImplementedError()

    def get_authorization_request_url(self, scopes, **kwargs):
        """ Constructs URL for auth code grant.
        Drop-in replacement for msal.ClientApplication method.
        """
        user_present = kwargs.pop('user_present', True)
        expanded_scopes = expand_veracity_scopes(scopes, user_present=user_present)
        return self.openid_client.build_auth_request_uri(
            'code', redirect_url=self.redirect_uri, scope=expanded_scopes, **kwargs)

    def initiate_auth_code_flow(self, scopes, **kwargs):
        """ Initiates auth code login flow for a user.
        Drop-in replacement for msal.ClientApplication method.

        Auth code flow is a "user present" scenario.

        References:
            - https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
        """
        import msal
        import uuid
        state = kwargs.pop('state', str(uuid.uuid4()))
        user_present = kwargs.pop('user_present', True)
        expanded_scopes = expand_veracity_scopes(scopes, user_present=user_present)
        decorated_scopes = msal.application.decorate_scope(expanded_scopes, self.client_id)
        return self.openid_client.initiate_auth_code_flow(
            scope=decorated_scopes,
            redirect_uri=self.redirect_uri,
            state=state,
            # Inject policy into query parameters.
            # This is the step where Veracity deviates from msal and azure.identity!
            p=self.authority.policy,
        )

    def remove_account(self, account):
        raise NotImplementedError()

    # #########################################################################
    # Overrides for msal.ConfidentialClientApplication
    # #########################################################################

    def acquire_token_for_client(self, scopes, **kwargs):
        user_present = kwargs.pop('user_present', False)
        expanded_scopes = expand_veracity_scopes(scopes, user_present=user_present)
        return self.openid_client.obtain_token_for_client(scope=expanded_scopes, **kwargs)

    def acquire_token_on_behalf_of(self, user_assertion, scopes, claims_challenge=None, **kwargs):
        import msal
        user_present = kwargs.pop('user_present', True)
        expanded_scopes = expand_veracity_scopes(scopes, user_present=user_present)
        decorated_scopes = msal.application.decorate_scope(expanded_scopes, self.client_id)
        data = kwargs.pop("data", {})
        data["requested_token_use"] = "on_behalf_of"
        data["claims"] = claims_challenge
        self.openid_client.obtain_token_by_refresh_token(
            user_assertion,
            self.openid_client.GRANT_TYPE_JWT,
            scope=decorated_scopes,
            data=data,
            **kwargs,
        )

    # #########################################################################
    # Veracity-specific methods
    # #########################################################################

    def validate_token(self, token, nonce=None):
        """ Validates an authoriation token.

        Returns:
            True if token is valid otherwise False.

        References:
            - https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#validating-tokens
            - https://github.com/AzureAD/microsoft-authentication-library-for-python/blob/dev/msal/oauth2cli/oidc.py
        """
        if token is None:
            raise IdentityError('Token is null')

        try:
            # msal includes a method to decode and validate ID tokens.
            decoded_token = oidc.decode_id_token(
                token,
                client_id=self.client_id,
                issuer=self.authority.issuer_endpoint,
                # TODO: Check nonce/state when validating.
                nonce=None,
            )
        except RuntimeError as err:
            raise IdentityError(f'ID token is invalid:\n{err}') from err

        return decoded_token

    def _save_token(self, token):
        """ Adds a token to the token cache.
        """
        token_data = oidc.decode_id_token(token['id_token'])
        try:
            userid = token_data['sub']
            user_tokens = self.token_cache.setdefault(userid, [])
            user_tokens.append(token)
        except KeyError as kerr:
            raise IdentityError("Malformed ID token has no 'sub' parameter.") from kerr


class Credential(object):
    """ A credential derived from Veracity. Can generate access tokens.

    Args:
        service (IdentityService): Veracity identity service which generated
            this credential.
    """

    def __init__(self, service):
        self.service = service

    def get_token(self, scopes, **kwargs):
        raise NotImplementedError('Do not use base class directly.')


class AuthorizationCodeCredential(Credential):
    pass


class InteractiveBrowserCredential(Credential):
    """ Veracity credential using system browser for user interaction.
    This is essentially a copy of the azure.identity.InteractiveBrowserCredential.

    Args:
        client_id (str): Client application ID.
        redirect_uri (str): Redirect URI for interactive flow.  Uses http://localhost
            by default.  For apps running on a user's computer you should only change
            this if you want to use a port other than 80.  Note, on Mac port 80 is
            not open by default; you will have to open it!  Whatever URI you choose
            here, it MUST be specified in the Veracity Developer Portal as your
            app's Reply URL.
        client_secret (str): Optional client secret.
    """

    def __init__(self, client_id, redirect_uri='http://localhost', client_secret=None):
        service = IdentityService(client_id, redirect_uri, client_secret=client_secret)
        super().__init__(service)

    def get_token(self, scopes, timeout=30):
        """ Get a user token interactively using the webbrowser.

        Internally this uses auth-code-flow to retrieve the token.  It creates a
        local HTTP server to handle the authorization response from Veracity.  For
        this to work on a user's local computer, you should set a Reply URL like
        http://localhost in the Veracity developer portal and provide that to
        the identity service.

        Args:
            scopes (list[str]): List of scopes to retrieve.  Do not include
                'openid', 'profile' or 'offline_access' - these get added
                automatically by the service.
            timeout (int): Time in seconds to wait for user to enter credentials.
        """

        import webbrowser

        # Start an HTTP server to receive the redirect.
        server = self._make_server(self.service.redirect_uri, timeout=timeout)
        if not server:
            raise IdentityError("Could not start an HTTP server for interactive credential.")

        flow = self.service.initiate_auth_code_flow(scopes, user_present=True)

        # Open system default browser to auth url.
        auth_url = flow['auth_uri']
        if not webbrowser.open(auth_url):
            raise IdentityError("Failed to open system web browser for interactive credential.")

        # Block until the server times out or receives the post-authentication redirect.  Then
        # we check the response for possible errors.
        response = server.wait_for_redirect()

        if not response:
            raise IdentityError(f"Timed out after waiting {timeout} seconds for the user to authenticate.")

        if "error" in response:
            err = response.get("error_description") or response["error"]
            raise IdentityError(f"Authentication failed: {err}")

        # Redeem the authorization code for a token.  This handles any errors with
        # malformed responses, so we don't have to.
        token = self.service.acquire_token_by_auth_code_flow(flow, server.query_params)
        return token

    def _make_server(self, redirect_uri, timeout=30):
        """ Starts an HTTP service on localhost to listen for browser redirects.
        This works the same as azure.identity.InteractiveBrowserCredential.
        """
        server = AuthCodeRedirectServer(redirect_uri, timeout)
        return server


class CertificateCredential(Credential):
    pass


class ChainedTokenCredential(Credential):
    pass


class ClientSecretCredential(Credential):
    """ Authenticates as a service principal (no user present).
    This is a drop-in replacement for azure.identity.ClientSecretCredential.

    Args:
        client_id (str): Client application ID.
        client_secret (str): Client secret (i.e. service principal password.)
            Remember, you should not store secrets in your code!  Use
            environment variables or Azure KeyVault instead.
    """

    def __init__(self, client_id, client_secret, resource=None, **kwargs):
        if resource is not None:
            # If we want to access a resource we need to use the v1 endpoints.  This
            # is quite a niche use case but is still in use in places.
            auth = Authority(api_version='v1.0')
            service = IdentityService(client_id, redirect_uri=None, client_secret=client_secret, authority=auth)
        else:
            service = IdentityService(client_id, redirect_uri=None, client_secret=client_secret)
        super().__init__(service)
        self.resource = resource

    def get_token(self, scopes, **kwargs):
        if self.resource is not None:
            # Inject the resource into the token request body.
            kwargs['data'] = {'resource': self.resource}
        return self.service.acquire_token_for_client(scopes, **kwargs)


class EnvironmentCredential(Credential):
    pass


class ManagedIdentityCredential(Credential):
    pass


class SharedTokenCacheCredential(Credential):
    pass


class DeviceCodeCredential(Credential):
    pass


class UsernamePasswordCredential(Credential):
    def __init__(self):
        raise NotImplementedError('Why are you storing user passwords? Use InteractiveBrowserCredential instead!')


class AuthCodeRedirectHandler(BaseHTTPRequestHandler):
    """ HTTP request handler to capture the authentication server's response.

    Copied from Microsoft's azure.identity._internal with a few edits.

    References:
        - https://github.com/Azure/azure-sdk-for-python
        - https://github.com/Azure/azure-sdk-for-python/blob/master/sdk/identity/
            azure-identity/azure/identity/_internal/auth_code_redirect_handler.py
    """
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs

        urlbits = urlparse(self.path)

        # If there are no query parameters, return and wait for the next request.
        if not urlbits.query:
            self.send_response(204)
            return

        # Take only the first of each parameter.
        self.server.query_params = {key: value[0] for key, value in parse_qs(urlbits.query).items()}

        # If there are query params, tell the user we have finished.
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"Veracity authentication complete. You can close this window.")

    def log_message(self, format, *args):
        pass  # this prevents server dumping messages to stdout


class AuthCodeRedirectServer(HTTPServer):
    """HTTP server that listens for the redirect request following an authorization code authentication.

    Copied from Microsoft's azure.identity._internal with a few edits.

    References:
        - https://github.com/Azure/azure-sdk-for-python
        - https://github.com/Azure/azure-sdk-for-python/blob/master/sdk/identity/
            azure-identity/azure/identity/_internal/auth_code_redirect_handler.py
    """

    query_params = {}

    def __init__(self, uri, timeout):
        from urllib.parse import urlparse
        urlbits = urlparse(uri)
        hostname = urlbits.hostname
        port = urlbits.port or 80
        super().__init__((hostname, port), AuthCodeRedirectHandler)
        self.timeout = timeout

    def wait_for_redirect(self):
        while not self.query_params:
            try:
                self.handle_request()
            except (IOError, ValueError):
                # Socket has been closed, probably by handle_timeout
                break

        # Ensure the underlying socket is closed (a no-op when the socket is already closed)
        self.server_close()

        # If we timed out, this returns an empty dict
        return self.query_params

    def handle_timeout(self):
        """ Break the request-handling loop by tearing down the server.
        """
        self.server_close()
