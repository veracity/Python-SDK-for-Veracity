""" Veracity Data Fabric API
"""


from typing import Any, AnyStr, Mapping, Sequence
from urllib.error import HTTPError
import pandas as pd
from azure.storage.blob.aio import ContainerClient
from .base import ApiBase


class DataFabricError(RuntimeError):
    pass


class DataFabricAPI(ApiBase):
    """ Access to the data fabric endpoints (/datafabric) in the Veracity API.


    All web calls are async using aiohttp.  Returns web responses exactly as
    received, usually JSON.

    Arguments:
        credential (veracity.Credential): Provides oauth access tokens for the
            API (the user has to log in to retrieve these unless your client
            application has permissions to use the service.)
        subscription_key (str): Your application's API subscription key.  Gets
            sent in th Ocp-Apim-Subscription-Key header.
        version (str): Not currently used.
    """

    API_ROOT = "https://api.veracity.com/veracity/datafabric"

    def __init__(self, credential, subscription_key, version=None, **kwargs):
        super().__init__(credential, subscription_key, scope=kwargs.pop('scope', 'veracity_datafabric'), **kwargs)
        self._url = f"{DataFabricAPI.API_ROOT}/data/api/1"
        self.sas_cache = {}
        self.access_cache = {}

    @property
    def url(self):
        return self._url

    # APPLICATIONS.

    async def get_current_application(self):
        url = f'{self._url}/application'
        resp = await self.session.get(url)
        data = await resp.json()
        if resp.status != 200:
            raise HTTPError(url, resp.status, data, resp.headers, None)
        return data

    async def get_application(self, applicationId):
        url = f'{self._url}/application/{applicationId}'
        resp = await self.session.get(url)
        data = await resp.json()
        if resp.status != 200:
            raise HTTPError(url, resp.status, data, resp.headers, None)
        return data

    async def add_application(self, *args, **kwargs):
        raise NotImplementedError()

    async def update_application_role(self, applicationId, role):
        url = f'{self._url}/application/{applicationId}?role={role}'
        resp = await self.session.get(url)
        data = await resp.json()
        if resp.status != 200:
            raise HTTPError(url, resp.status, data, resp.headers, None)
        return data

    # GROUPS.

    async def get_groups(self):
        raise NotImplementedError()

    async def add_group(self, *args, **kwargs):
        raise NotImplementedError()

    async def get_group(self, groupId):
        raise NotImplementedError()

    async def update_group(self, groupId, *args, **kwargs):
        raise NotImplementedError()

    async def delete_group(self, groupId):
        raise NotImplementedError()

    # KEY TEMPLATES.

    async def get_keytemplates(self):
        url = f'{self._url}/keytemplates'
        resp = await self.session.get(url)
        data = await resp.json()
        if resp.status != 200:
            raise HTTPError(url, resp.status, data, resp.headers, None)
        return data

    # LEDGER.

    async def get_ledger(self, containerId: AnyStr) -> pd.DataFrame:
        url = f'{self._url}/resource/{containerId}/ledger'
        resp = await self.session.get(url)
        data = await resp.json()
        if resp.status == 200:
            df = pd.DataFrame(data)
            df['dateOfEvent'] = pd.to_datetime(df['dateOfEvent'], format="%Y-%m-%dT%H:%M:%SZ")
            return df
        elif resp.status == 403:
            raise DataFabricError(f'HTTP/403 Must be data owner or steward to view container {containerId} ledger. Details:\n{data}')
        elif resp.status == 404:
            raise DataFabricError(f'HTTP/404 Data Fabric container {containerId} does not exist. Details:\n{data}')
        else:
            raise HTTPError(url, resp.status, data, resp.headers, None)

    # RESOURCES.

    # ACCESS.

    async def get_best_access(self, containerId: AnyStr) -> pd.Series:
        """ Gets the best available access share ID for a Veracity container.
        Returns the access share ID with the highest available privileges.
        """
        app = await self.get_current_application()
        all_accesses = await self.get_accesses_df(containerId)
        my_accesses = all_accesses[all_accesses['userId'] == app['id']]
        best_index = my_accesses['level'].astype(float).idxmax()
        return my_accesses.loc[best_index]

    async def get_accesses(self, resourceId: AnyStr, pageNo: int = 1, pageSize: int = 50) -> Mapping[AnyStr, Any]:
        url = f'{self._url}/resources/{resourceId}/accesses?pageNo={pageNo}&pageSize={pageSize}'
        resp = await self.session.get(url)
        if resp.status != 200:
            raise HTTPError(url, resp.status, await resp.text(), resp.headers, None)
        data = await resp.json()
        return data

    async def get_accesses_df(self, resourceId: AnyStr, pageNo: int = 1, pageSize: int = 50) -> pd.DataFrame:
        """ Gets the access levels as a dataframe, including the "level" value.
        """
        import pandas as pd
        data = await self.get_accesses(resourceId, pageNo, pageSize)
        df = pd.DataFrame(data['results'])
        # Add the level values for future use.
        df['level'] = self._access_levels(df)
        self.access_cache[resourceId] = df
        return df

    async def share_access(self, resourceId: AnyStr, autoRefresh: bool, *args, **kwargs):
        raise NotImplementedError()

    async def revoke_access(self, resourceId: AnyStr, accessId: AnyStr):
        raise NotImplementedError()

    async def get_sas(self, resourceId: AnyStr, accessId: AnyStr = None, **kwargs) -> pd.DataFrame:
        key = self.get_sas_cached(resourceId) or await self.get_sas_new(resourceId, accessId, **kwargs)
        return key

    async def get_sas_new(self, resourceId: AnyStr, accessId: AnyStr = None, **kwargs) -> pd.DataFrame:
        """ Gets a new SAS key to access a container.

        You can request a key with a specific access level (if you have the
        accessId).  By default this method will attempt to get the most
        permissive access level available for the active credential.

        Args:
            resourceId (str): The container ID.
            accessId (str): Access level ID, optional.
        """
        if accessId is not None:
            access_id = accessId
        else:
            access = await self.get_best_access(resourceId)
            access_id = access.get('accessSharingId')

        assert access_id is not None, 'Could not find access rights for current user.'
        url = f'{self._url}/resources/{resourceId}/accesses/{access_id}/key'
        resp = await self.session.put(url)
        data = await resp.json()
        if resp.status != 200:
            raise HTTPError(url, resp.status, data, resp.headers, None)
        # The API response does not include the access ID; we add for future use.
        data['accessId'] = access_id
        self.sas_cache[resourceId] = data
        return data

    def get_sas_cached(self, resourceId: AnyStr) -> pd.DataFrame:
        from datetime import datetime, timezone
        import dateutil
        sas = self.sas_cache.get(resourceId)
        if not sas:
            return None
        expiry = dateutil.parser.isoparse(sas['sasKeyExpiryTimeUTC'])
        if (not sas['isKeyExpired']) and (datetime.now(timezone.utc) < expiry):
            return sas
        else:
            # Remove the expired key from the cache.
            self.sas_cache.pop(resourceId)
            return None

    def _access_levels(self, accesses: pd.DataFrame) -> pd.Series:
        """ Calculates an access "level" for each access in a dataframe.
        In general higher access level means more privileges.

        Notes:
            Attributes related to permissions in this way:

                | Attribute  | Permission | Score |
                | ---------  | ---------- | ----- |
                | attribute1 | Read       |   4   |
                | attribute2 | Write      |   1   |
                | attribute3 | Delete     |   8   |
                | attribute4 | List       |   2   |

            Scores are additive, so "read, write & list" = 7.  If you want to
            check an access has delete privileges, use level >= 8.

            Write is considered the lowest privilege as it does not allow data to
            be seen.

        Args:
            accesses (pandas.DataFrame): Accesses as returned by :meth:`get_accesses`.

        Returns:
            Pandas Series with same index as input.
        """
        import numpy as np
        scores = np.array([4, 1, 8, 2])
        attrs = accesses[['attribute1', 'attribute2', 'attribute3', 'attribute4']].to_numpy()
        levels = (attrs * scores).sum(axis=1)
        return pd.Series(levels, index=accesses.index, dtype='Int64')

    # DATA STEWARDS.

    async def get_data_stewards(self, resourceId: AnyStr) -> Sequence:
        raise NotImplementedError()

    async def get_data_stewards_df(self, resourceId: AnyStr) -> pd.DataFrame:
        raise NotImplementedError()

    async def delegate_data_steward(self, resourceId: AnyStr, userId: AnyStr, *args, **kwargs) -> Sequence:
        raise NotImplementedError()

    async def delete_data_steward(self, resourceId: AnyStr, userId: AnyStr):
        raise NotImplementedError()

    async def transfer_ownership(self, resourceId: AnyStr, userId: AnyStr, keepaccess: bool = False):
        raise NotImplementedError()

    # TAGS.

    async def get_tags(self, includeDeleted: bool = False, includeNonVeracityApproved: bool = False) -> Sequence:
        raise NotImplementedError()

    async def add_tags(self, *args, **kwargs):
        raise NotImplementedError()

    # USERS.

    async def get_shared_users(self, userId: AnyStr) -> Sequence:
        raise NotImplementedError()

    async def get_current_user(self) -> Mapping:
        raise NotImplementedError()

    async def get_user(self, userId: AnyStr) -> Mapping:
        raise NotImplementedError()

    # CONTAINERS.

    async def get_container(self, containerId: AnyStr, **kwargs) -> ContainerClient:
        """ Gets Veracity container client (using Azure Storage SDK.)
        """
        sas = await self.get_sas(containerId, **kwargs)
        sasurl = sas['fullKey']
        return ContainerClient.from_container_url(sasurl)
