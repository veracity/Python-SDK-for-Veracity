""" Veracity Services API
"""

from . import ApiBase
# TODO: Define a custom API exception.
from urllib.error import HTTPError


class UserAPI(ApiBase):
    """ Access to the current user endpoints (/my) in the Veracity REST-API.

    All web calls are async using aiohttp.  Returns web responses exactly as
    received, usually JSON.

    Arguments:
        credential (veracity.Credential): Provides oauth access tokens for the
            API (the user has to log in to retrieve these unless your client
            application has permissions to use the service.)
        subscription_key (str): Your application's API subscription key.  Gets
            sent in th Ocp-Apim-Subscription-Key header.
        version (str): Must be "v3" - other API versions not yet supported.
    """

    API_ROOT = "https://api.veracity.com/veracity/services"

    def __init__(self, credential, subscription_key, version="v3", **kwargs):
        super().__init__(credential, subscription_key, **kwargs)
        self._url = f"{API_ROOT}/{version}/my"

    @property
    def url(self):
        return self._url

    async def get_companies(self):
        endpoint = f'{self.url}/companies'
        resp = await self.session.get(endpoint)
        data = await resp.json()
        if resp.status != 200:
            raise HTTPError(endpoint, resp.status, data, resp.headers, None)
        return data

    async def get_messages(self, all=False):
        raise NotImplementedError()

    async def get_message_count(self):
        raise NotImplementedError()

    async def get_message(self, messageId):
        raise NotImplementedError()

    async def validate_policies(self, returnUrl):
        raise NotImplementedError()

    async def validate_service_policy(self):
        raise NotImplementedError()

    async def get_profile(self):
        endpoint = f'{self.url}/profile'
        resp = await self.session.get(endpoint)
        data = await resp.json()
        if resp.status != 200:
            raise HTTPError(endpoint, resp.status, data, resp.headers, None)
        return data

    async def get_services(self):
        raise NotImplementedError()

    async def get_widgets(self):
        raise NotImplementedError()


class ClientAPI(ApiBase):
    """ Access to the app client endpoints (/this) in the Veracity REST-API.

    All web calls are async using aiohttp.  Returns web responses exactly as
    received, usually JSON.

    Arguments:
        credential (veracity.Credential): Provides oauth access tokens for the
            API (the user has to log in to retrieve these unless your client
            application has permissions to use the service.)
        subscription_key (str): Your application's API subscription key.  Gets
            sent in th Ocp-Apim-Subscription-Key header.
        version (str): Must be "v3" - other API versions not yet supported.
    """

    API_ROOT = "https://api.veracity.com/veracity/services"

    def __init__(self, credential, subscription_key, version="v3", **kwargs):
        super().__init__(credential, subscription_key, **kwargs)
        self._url = f"{ClientAPI.API_ROOT}/{version}/this"

    @property
    def url(self):
        return self._url

    async def get_services(self, page, pageSize=10):
        raise NotImplementedError()

    async def post_notification(self, name, content, id_, timeStamp, recipients,
                                serviceId, channelId=None, type_=0,
                                highPriority=False):
        raise NotImplementedError()

    async def get_subscribers(self, page, pageSize=10, serviceId=None):
        raise NotImplementedError()

    async def get_subscriber(self, userId, serviceId=None):
        raise NotImplementedError()

    async def add_subscriber(self, userId, role, serviceId=None):
        raise NotImplementedError()

    async def remove_subscriber(self, userId, serviceId=None):
        raise NotImplementedError()

    async def create_user(self, firstName, lastName, email, role, contactEmail,
                          contactName, returnUrl, sendMail=True,
                          createSubscription=True):
        raise NotImplementedError()

    async def get_user_from_email(self, email):
        raise NotImplementedError()
