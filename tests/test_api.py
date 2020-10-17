import asyncio
import contextlib
import pytest
from unittest import mock
from aiohttp import ClientSession, ClientResponse
from aiohttp.client_exceptions import ClientResponseError

from pmgaiorest import ApiBase

RESP_JSON = '{"hello": 123}'
RESP_HEADERS = '{"Content-Type": "application/json"}'

REQ_BASE = 'http://base.com'
REQ_ENDPOINT = 'myep'
REQ_URL = f'{REQ_BASE}/{REQ_ENDPOINT}'
REQ_AUTH_ARGS = {'token_type': 'Bearer', 'access_token': 'acc_tok'}
REQ_HEADERS = {'Content-Type': 'application/json', 'Authorization': 'Bearer acc_tok', 'Accept': 'application/json'}

@pytest.fixture
def base_session():
    with mock.patch('aiohttp.client.ClientSession', spec=ClientSession, new=mock.AsyncMock()) as session:
        yield session

@pytest.fixture
def session(base_session, resp200):
    base_session.get = mock.AsyncMock(return_value=resp200)
    base_session.post = mock.AsyncMock(return_value=resp200)
    return base_session

@pytest.fixture
def resp200():
    return create_response(status=200)

@pytest.fixture
def resp401():
    return create_response(status=401)

@pytest.fixture
def api_base(session):
    return ApiBase(session, REQ_BASE, REQ_AUTH_ARGS)

@pytest.fixture
def bad_good_get(resp401, resp200):
    def bad_good_get_ret(*args, **kwargs):
        headers = kwargs['headers']
        if headers['Authorization'] == 'Bearer acc_tok':
            return resp401
        if headers['Authorization'] == 'Bearer acc_tok_after_connect':
            return resp200
        raise Exception("should not get here")
    return bad_good_get_ret

def create_response(*, status):
    resp = mock.AsyncMock(spec=ClientResponse)
    resp.status = status
    resp.headers = RESP_HEADERS
    resp.json = mock.AsyncMock(return_value=RESP_JSON)
    def rfs():
        raise ClientResponseError(None, None, status=status)
    resp.raise_for_status = mock.MagicMock(side_effect=rfs)
    return resp

@pytest.mark.asyncio
async def test_get(session, api_base):
    json = await api_base.get(REQ_ENDPOINT)

    assert json == RESP_JSON
    session.get.assert_called_once_with(REQ_URL, headers=REQ_HEADERS)

@pytest.mark.asyncio
async def test_post(session, api_base):
    json = await api_base.post(REQ_ENDPOINT)

    assert json == RESP_JSON
    session.post.assert_called_once_with(REQ_URL,
            headers=REQ_HEADERS)

@pytest.mark.asyncio
async def test_get_with_headers(session, api_base):
    json, headers = await api_base.get_with_headers(REQ_ENDPOINT)

    assert json == RESP_JSON
    assert headers == RESP_HEADERS
    session.get.assert_called_once_with(REQ_URL,
            headers=REQ_HEADERS)

@pytest.mark.asyncio
async def test_raises_on_auth(base_session, resp401):
    ' auth fails no reconnect handler'

    base_session.get = mock.AsyncMock(return_value=resp401)

    api_base = ApiBase(base_session, REQ_BASE, REQ_AUTH_ARGS)

    with pytest.raises(ClientResponseError):
        await api_base.get(REQ_ENDPOINT)

@pytest.mark.asyncio
async def test_reconnects_on_auth(base_session, bad_good_get):
    ' auth fails - reconnect - auth succeeds'
    base_session.get = mock.AsyncMock(side_effect=bad_good_get)

    def handle_reconnect():
        return {'token_type': 'Bearer', 'access_token': 'acc_tok_after_connect'}

    api_base = ApiBase(base_session,REQ_BASE, REQ_AUTH_ARGS,
            handle_reconnect=handle_reconnect)

    json = await api_base.get(REQ_ENDPOINT)

@pytest.mark.asyncio
async def test_raises_on_auth_if_reconnect_fails(base_session, resp401):
    ' auth fails, reconnect handler returns None'

    base_session.get = mock.AsyncMock(return_value=resp401)

    def handle_reconnect():
        return None

    api_base = ApiBase(base_session, REQ_BASE, REQ_AUTH_ARGS,
            handle_reconnect=handle_reconnect)

    with pytest.raises(ClientResponseError):
        await api_base.get(REQ_ENDPOINT)

@pytest.mark.asyncio
async def test_raises_on_auth_if_reconnect_invalid(base_session, bad_good_get):
    ' auth fails, reconnect handler returns None'
    base_session.get = mock.AsyncMock(side_effect=bad_good_get)

    def handle_reconnect():
        # return the same so should fail again
        return {'token_type': 'Bearer', 'access_token': 'acc_tok'}

    api_base = ApiBase(base_session, REQ_BASE, REQ_AUTH_ARGS,
            handle_reconnect=handle_reconnect)

    with pytest.raises(ClientResponseError):
        await api_base.get(REQ_ENDPOINT)

