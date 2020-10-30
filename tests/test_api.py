import asyncio
import contextlib
import pytest
from unittest import mock
from aiohttp import ClientSession, ClientResponse, ClientResponseError, BasicAuth

from pmgaiorest import ApiBase
from pmgaiorest.testing.fixtures import resp401, resp200, session, base_session

REQ_BASE = 'http://base.com/api_v1/2.0'
REQ_ENDPOINT = 'myep'
REQ_URL = f'{REQ_BASE}/{REQ_ENDPOINT}'
REQ_AUTH_ARGS = {'token_type': 'Bearer', 'access_token': 'acc_tok'}
REQ_BASE_HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
REQ_HEADERS = {'Content-Type': 'application/json', 'Authorization': 'Bearer acc_tok', 'Accept': 'application/json'}

@pytest.mark.usefixtures('session')
@pytest.fixture
def api_base(session):
    return ApiBase(session, REQ_BASE, header_args=REQ_AUTH_ARGS)

@pytest.mark.usefixtures('resp401', 'resp200')
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

@pytest.mark.usefixtures('session', 'api_base')
@pytest.mark.asyncio
async def test_get(session, api_base, resp200):
    json = await api_base.get(REQ_ENDPOINT)

    assert json == resp200._json
    session.get.assert_called_once_with(REQ_URL, headers=REQ_HEADERS)

@pytest.mark.usefixtures('session', 'api_base')
@pytest.mark.asyncio
async def test_get_with_auth(session, api_base, resp200):
    auth=BasicAuth('user', 'password')
    api_base = ApiBase(session, REQ_BASE, auth=auth)
    json = await api_base.get(REQ_ENDPOINT)

    assert json == resp200._json
    session.get.assert_called_once_with(REQ_URL, auth=auth, headers=REQ_BASE_HEADERS)

@pytest.mark.usefixtures('session', 'api_base')
@pytest.mark.asyncio
async def test_get_no_base(session, api_base, resp200):
    json = await api_base.get(None, full_path='v2/different')

    assert json == resp200._json
    session.get.assert_called_once_with('http://base.com/v2/different', headers=REQ_HEADERS)

@pytest.mark.usefixtures('session', 'api_base')
@pytest.mark.asyncio
async def test_get_update_headers(session, api_base, resp200):
    json = await api_base.get(REQ_ENDPOINT)

    assert json == resp200._json
    session.get.assert_called_once_with(REQ_URL, headers=REQ_HEADERS)
    session.get.reset_mock()

    api_base.update_header_args({'access_token': 'new_acc_tok'})

    json = await api_base.get(REQ_ENDPOINT)
    assert json == resp200._json
    new_heads = {'Content-Type': 'application/json', 'Authorization': 'Bearer new_acc_tok', 'Accept': 'application/json'}
    session.get.assert_called_once_with(REQ_URL, headers=new_heads)

@pytest.mark.usefixtures('session', 'api_base')
@pytest.mark.asyncio
async def test_get_add_to_headers(session, api_base, resp200):
    json = await api_base.get(REQ_ENDPOINT)

    assert json == resp200._json
    session.get.assert_called_once_with(REQ_URL, headers=REQ_HEADERS)
    session.get.reset_mock()

    def _dif_headers(*args, **kwargs):
        return {'stuff': 'stufff'}

    api_base.create_headers = _dif_headers # override the method
    api_base.update_header_args({})

    json = await api_base.get(REQ_ENDPOINT)
    assert json == resp200._json
    session.get.assert_called_once_with(REQ_URL, headers={'stuff': 'stufff'})

@pytest.mark.usefixtures('session', 'api_base')
@pytest.mark.asyncio
async def test_post(session, api_base, resp200):
    json = await api_base.post(REQ_ENDPOINT)

    assert json == resp200._json
    session.post.assert_called_once_with(REQ_URL,
            headers=REQ_HEADERS)

@pytest.mark.usefixtures('session', 'api_base')
@pytest.mark.asyncio
async def test_get_with_headers(session, api_base, resp200):
    json, headers = await api_base.get_with_headers(REQ_ENDPOINT)

    assert json == resp200._json
    assert headers == resp200.headers
    session.get.assert_called_once_with(REQ_URL,
            headers=REQ_HEADERS)

@pytest.mark.usefixtures('base_session', 'resp401')
@pytest.mark.asyncio
async def test_raises_on_auth(base_session, resp401):
    ' auth fails no reconnect handler'

    base_session.get = mock.AsyncMock(return_value=resp401)

    api_base = ApiBase(base_session, REQ_BASE, header_args=REQ_AUTH_ARGS)

    with pytest.raises(ClientResponseError):
        await api_base.get(REQ_ENDPOINT)

@pytest.mark.usefixtures('base_session', 'bad_good_get')
@pytest.mark.asyncio
async def test_reconnects_on_auth(base_session, bad_good_get):
    ' auth fails - reconnect - auth succeeds'
    base_session.get = mock.AsyncMock(side_effect=bad_good_get)

    def handle_reconnect():
        return {'token_type': 'Bearer', 'access_token': 'acc_tok_after_connect'}

    api_base = ApiBase(base_session,REQ_BASE, header_args=REQ_AUTH_ARGS,
            handle_reconnect=handle_reconnect)

    json = await api_base.get(REQ_ENDPOINT)

@pytest.mark.usefixtures('base_session', 'resp401')
@pytest.mark.asyncio
async def test_raises_on_auth_if_reconnect_fails(base_session, resp401):
    ' auth fails, reconnect handler returns None'

    base_session.get = mock.AsyncMock(return_value=resp401)

    def handle_reconnect():
        return None

    api_base = ApiBase(base_session, REQ_BASE, header_args=REQ_AUTH_ARGS,
            handle_reconnect=handle_reconnect)

    with pytest.raises(ClientResponseError):
        await api_base.get(REQ_ENDPOINT)

@pytest.mark.usefixtures('base_session', 'bad_good_get')
@pytest.mark.asyncio
async def test_raises_on_auth_if_reconnect_invalid(base_session, bad_good_get):
    ' auth fails, reconnect handler returns None'
    base_session.get = mock.AsyncMock(side_effect=bad_good_get)

    def handle_reconnect():
        # return the same so should fail again
        return {'token_type': 'Bearer', 'access_token': 'acc_tok'}

    api_base = ApiBase(base_session, REQ_BASE, header_args=REQ_AUTH_ARGS,
            handle_reconnect=handle_reconnect)

    with pytest.raises(ClientResponseError):
        await api_base.get(REQ_ENDPOINT)

