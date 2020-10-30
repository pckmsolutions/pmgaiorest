import asyncio
import pytest
from unittest import mock
from aiohttp import ClientSession, ClientResponse, ClientResponseError, BasicAuth

RESP_JSON = '{"hello": 123}'
RESP_HEADERS = '{"Content-Type": "application/json"}'

@pytest.fixture
def base_session():
    with mock.patch('aiohttp.client.ClientSession', spec=ClientSession, new=mock.AsyncMock()) as session:
        yield session

@pytest.fixture
def resp200():
    return create_response(status=200)

@pytest.fixture
def resp401():
    return create_response(status=401)

@pytest.mark.usefixtures('base_session', 'resp200')
@pytest.fixture
def session(base_session, resp200):
    base_session.get = mock.AsyncMock(return_value=resp200)
    base_session.post = mock.AsyncMock(return_value=resp200)
    return base_session

def create_response(*, status):
    resp = mock.AsyncMock(spec=ClientResponse)
    resp.status = status
    resp.headers = RESP_HEADERS
    resp._json = RESP_JSON
    resp.json = mock.AsyncMock(return_value=resp._json)
    def rfs():
        raise ClientResponseError(None, None, status=status)
    resp.raise_for_status = mock.MagicMock(side_effect=rfs)
    return resp
