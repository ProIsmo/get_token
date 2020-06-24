import re
import asyncio
import aiohttp
import xml.etree.ElementTree as Et

from urllib.parse import urlparse


async def my_games(session, server, email: str, password: str, proxy: str = None):
    auth_headers = {'User-Agent': 'Downloader/15740'}
    ChannelId = 35
    ProjectId = 1177 if server in ['ru-alpha', 'ru-bravo', 'ru-charlie'] else 2000076

    if proxy:
        if not urlparse(proxy).port:
            return 'Proxy failed (NO PORT PASSED)'

        if urlparse(proxy).scheme != 'http':
            return 'Proxy failed (Only http proxies are supported)'

    if email.split('@')[1] in ['mail.ru', 'inbox.ru', 'list.ru', 'bk.ru']:
        ShardId = 0 if server == 'ru-alpha' else 1 if server == 'ru-bravo' else 2

        mailru_auth = await (await session.post('https://auth-ac.my.games/social/mailru', proxy=proxy)).text()
        mailru_state = re.search(r'state=([\d\w]+)', mailru_auth, re.IGNORECASE).group(1)

        await session.post('https://account.mail.ru', proxy=proxy)
        act = session.cookie_jar.filter_cookies('https://account.mail.ru')
        act_token = re.search(r'act=([\d\w]+)', str(act['act']), re.IGNORECASE).group(1)

        data = {
            'Referer': 'https://account.mail.ru/login?opener=o2',
            'Origin': 'https://account.mail.ru',
            'Content-Type': 'application/x-www-form-urlencoded',
            'username': email,
            'Login': email,
            'Password': password,
            'password': password,
            'act_token': act_token,
            'page': f'https://o2.mail.ru/xlogin?authid=kbjooyiv.dej&client_id=bbddb88d19b84a62aedd1ffbc71af201&force_us=1&from=o2&logo_target=_none&no_biz=1&redirect_uri=https%3A%2F%2Fauth-ac.my.games%2Fsocial%2Fmailru_callback%2F&remind_target=_self&response_type=code&scope=&signup_target=_self&state={mailru_state}',
            'new_auth_form': '1',
            'FromAccount': 'opener=o2&twoSteps=1',
            'lang': 'en_US'
        }
        await session.post('https://auth.mail.ru/cgi-bin/auth', headers=auth_headers, data=data, proxy=proxy)

        o2csrf = session.cookie_jar.filter_cookies('https://o2.mail.ru/')

        if not o2csrf.get('o2csrf'):
            return 'Authentication failed (O2CSRF)'

        o2csrf_token = re.search(r'o2csrf=([\d\w]+)', str(o2csrf['o2csrf']), re.IGNORECASE).group(1)

        data = {
            'Page': f'https://o2.mail.ru/login?client_id=bbddb88d19b84a62aedd1ffbc71af201&response_type=code&scope=&redirect_uri=https%3A%2F%2Fauth-ac.my.games%2Fsocial%2Fmailru_callback%2F&state=${mailru_state}&no_biz=1',
            'FailPage': f'https://o2.mail.ru/login?client_id=bbddb88d19b84a62aedd1ffbc71af201&response_type=code&scope=&redirect_uri=https%3A%2F%2Fauth-ac.my.games%2Fsocial%2Fmailru_callback%2F&state=${mailru_state}&no_biz=1&fail=1',
            'Referer': f'https://o2.mail.ru/xlogin?client_id=bbddb88d19b84a62aedd1ffbc71af201&response_type=code&scope=&redirect_uri=https%3A%2F%2Fauth-ac.my.games%2Fsocial%2Fmailru_callback%2F&state=${mailru_state}&no_biz=1&force_us=1&signup_target=_self&remind_target=_self&logo_target=_none',
            'Origin': 'https://o2.mail.ru',
            'login': email,
            'o2csrf': o2csrf_token,
            'mode': ''
        }
        await session.post(f'https://o2.mail.ru/login', data=data, headers=auth_headers, proxy=proxy)

        sdc_data = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://o2.mail.ru/xlogin',
            'Origin': 'https://o2.mail.ru'
        }
        await session.post('https://auth-ac.my.games/sdc?from=https%3A%2F%2Fapi.my.games%2Fsocial%2Fprofile%2Fsession&JSONP_call=callback1522169', data=sdc_data, headers=auth_headers, proxy=proxy)

    else:
        ShardId = 1 if server == 'eu' else 2

        payload = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://api.my.games',
            'Referer': 'https://api.my.games/gamecenter/login/?lang=en_US',
        }

        login_data = {
            'email': email,
            'password': password,
            'continue': 'https://auth-ac.my.games/sdc?from=https%3A%2F%2Fapi.my.games%2Fgamecenter%2Flogin_finished%2F',
            'failure': 'https://api.my.games/gamecenter/login/',
            'nosavelogin': '0'
        }
        while True:
            try:
                response = await session.post('https://auth-ac.my.games/auth', headers=payload, data=login_data, allow_redirects=False, proxy=proxy)
                for i in range(0, 2):
                    response = await session.get(response.headers['location'], allow_redirects=False, proxy=proxy)
            except:
                continue
            break

    token = session.cookie_jar.filter_cookies('https://api.my.games')

    if not token.get('mc'):
        return 'Authentication failed (MC)'
    if not token.get('sdcs'):
        return 'Authentication failed (SDCS)'

    mc = re.search(r'mc=([\d\w]+)', str(token['mc']), re.IGNORECASE).group(1)
    sdcs = re.search(r'sdcs=([\d\w]+)', str(token['sdcs']), re.IGNORECASE).group(1)

    auth_data = f'<?xml version="1.0" encoding="UTF-8"?><Auth mc="{mc}" sdcs="{sdcs}" ChannelId="{ChannelId}" GcLang="en" UserId="" UserId2=""/>'
    auth_post = await (await session.post('https://authdl.my.games/gem.php?hint=Auth', data=auth_data, headers=auth_headers, proxy=proxy)).text()

    auth_code_group = re.search(r'SessionKey="([\d\w]+)"', auth_post, re.IGNORECASE)

    if not auth_code_group:
        if Et.fromstring(auth_post).get('ErrorCode') == 505:
            psession = await (await session.post('https://api.my.games/social/profile/session', headers=auth_headers, proxy=proxy)).json()
            psession_data = {
                'csrfmiddlewaretoken_jwt': psession['token'],
                'csrfmiddlewaretoken': ''
            }
            await session.post('https://api.my.games/account/terms_accept/', data=psession_data, headers=auth_headers, proxy=proxy)
            return 'Authentication failed (EULA)'
        return 'Authentication failed (Auth)'

    session_key = auth_code_group.group(1)
    login_data = f'<Login SessionKey="{session_key}" ProjectId="{ProjectId}" ShardId="{ShardId}"/>'

    response_login = await (await session.post('https://authdl.my.games/gem.php?hint=Login', data=login_data, headers=auth_headers, proxy=proxy)).text()

    if Et.fromstring(response_login).get('ErrorCode'):
        return 'Authentication failed (Session)'

    account_id = re.search(r'GameAccount="([\d\w]+)"', response_login, re.IGNORECASE).group(1)
    token = re.search(r'Code="([\d\w]+)"', response_login, re.IGNORECASE).group(1)
    return account_id, token


async def main():
    session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=False))
    await my_games(session=session, server="", email="", password="", proxy="")
    await session.close()


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
