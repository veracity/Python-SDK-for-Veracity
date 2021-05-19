""" Unit tests for the data fabric API.
"""

import pytest
from veracity_platform import data


@pytest.fixture(scope='module')
def credential(CLIENT_ID, CLIENT_SECRET, RESOURCE_URL):
    from veracity_platform import identity
    yield identity.ClientSecretCredential(CLIENT_ID, CLIENT_SECRET, resource=RESOURCE_URL)


@pytest.mark.requires_secrets
@pytest.mark.requires_datafabric
class TestDataFabricAPI(object):

    @pytest.fixture()
    async def api(self, credential, SUBSCRIPTION_KEY):
        try:
            api = data.DataFabricAPI(credential, SUBSCRIPTION_KEY)
            await api.connect()
            yield api
        finally:
            await api.disconnect()

    @pytest.mark.asyncio
    async def test_connect(self, credential, SUBSCRIPTION_KEY):
        api = data.DataFabricAPI(credential, SUBSCRIPTION_KEY)
        assert api is not None
        try:
            await api.connect()
        finally:
            await api.disconnect()

    @pytest.mark.asyncio
    async def test_ledger(self, api, CONTAINER_ID):
        """ Get ledger from a demo container.
        """
        data = await api.get_ledger(CONTAINER_ID)
        assert data is not None

    @pytest.mark.asyncio
    async def test_get_accesses(self, api, CONTAINER_ID):
        """ Get all access shares for a demo container.
        """
        data = await api.get_accesses(CONTAINER_ID)
        assert data is not None
        assert 'results' in data
        assert 'page' in data and data['page'] == 1

    @pytest.mark.asyncio
    async def test_get_best_access(self, api, CONTAINER_ID):
        """ Get an access share ID for a demo container.
        Note, we cannot test precisely the access because it depends on the
        test environment.
        """
        data = await api.get_best_access(CONTAINER_ID)
        assert data is not None

    @pytest.mark.asyncio
    async def test_sas_new(self, api, CONTAINER_ID):
        """ Get new SAS key for a demo container.
        """
        sas = await api.get_sas_new(CONTAINER_ID)
        assert sas is not None

    @pytest.mark.asyncio
    async def test_sas_cached(self, api, CONTAINER_ID):
        """ Get new SAS key for a demo container.
        """
        # First ensure there is a SAS in the cache.
        sasnew = await api.get_sas_new(CONTAINER_ID)
        sas = api.get_sas_cached(CONTAINER_ID)
        assert sas == sasnew

    def test_access_level(self, api):
        import pandas as pd
        import pandas.testing as pdt
        accesses = pd.DataFrame(
            columns=['attribute1', 'attribute2', 'attribute3', 'attribute4'],
            data=[
                [False, True, False, False],  # Write.
                [True, False, False, True],  # Read and list.
                [True, True, False, True],  # Read, write and list.
                [True, True, True, True],  # Read, write, list and delete.
                [False, False, False, True],  # List.
            ]
        )
        expected = pd.Series([1, 6, 7, 15, 2], dtype='Int64')
        levels = api._access_levels(accesses)
        pdt.assert_series_equal(expected, levels)
