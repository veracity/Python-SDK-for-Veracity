""" Global pytest configuration and fixtures.


We read several test settings from environment variables so we don't have to
store client IDs and secrets in the code.
"""

import os
import pytest


@pytest.fixture(scope='session', autouse=True)
def configure_pandas():
    import pandas as pd
    pd.options.display.max_columns = 10
    pd.options.display.max_rows = 100


@pytest.fixture(scope='session')
def CLIENT_ID():
    return os.environ.get("TEST_VERACITY_CLIENT_ID")


@pytest.fixture(scope='session')
def CLIENT_SECRET():
    return os.environ.get("TEST_VERACITY_CLIENT_SECRET")


@pytest.fixture(scope='session')
def SUBSCRIPTION_KEY():
    return os.environ.get("TEST_VERACITY_SUBSCRIPTION_KEY")


@pytest.fixture(scope='session')
def RESOURCE_URL():
    return os.environ.get("TEST_VERACITY_RESOURCE_URL")


@pytest.fixture(scope='session')
def CONTAINER_ID():
    return os.environ.get("TEST_VERACITY_CONTAINER_ID")


@pytest.fixture(scope='session', autouse=True)
def requires_secrets(request, CLIENT_ID, CLIENT_SECRET, SUBSCRIPTION_KEY):
    missing_secrets = (CLIENT_ID is None) or (CLIENT_SECRET is None) or (SUBSCRIPTION_KEY is None)
    if missing_secrets:
        pytest.skip('Test environment variable(s) not set.')


@pytest.fixture(scope='session', autouse=True)
def requires_datafabric(request, RESOURCE_URL, CONTAINER_ID):
    missing_vars = (RESOURCE_URL is None) or (CONTAINER_ID is None)
    if missing_vars:
        pytest.skip('Test environment variable(s) for data fabric not set.')
