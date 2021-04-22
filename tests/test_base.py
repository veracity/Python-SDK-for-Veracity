""" Unit tests for shared components.
"""

import pytest
from veracity_platform import base


@pytest.fixture(scope='module')
def credential(CLIENT_ID, CLIENT_SECRET):
    from veracity_platform import identity
    yield identity.ClientSecretCredential(CLIENT_ID, CLIENT_SECRET)


@pytest.mark.requires_secrets
class TestApiBase(object):

    @pytest.mark.asyncio
    async def test_connect(self, credential, SUBSCRIPTION_KEY):
        api = base.ApiBase(credential, SUBSCRIPTION_KEY, scope='veracity_service')
        assert api is not None
        try:
            await api.connect()
            print(api._headers)
        finally:
            await api.disconnect()
