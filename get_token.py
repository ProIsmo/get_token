import re
import asyncio
import aiohttp


async def my_games(session, server, email: str, password: str):
    auth_headers = {'User-Agent': 'Downloader/15740'}
    ChannelId = 35
    ProjectId = 1177 if server in ['ru-alpha', 'ru-bravo', 'ru-charlie'] else 2000076

    if email.split('@')[1] in ['mail.ru', 'inbox.ru']:

        ShardId = 0 if server == 'ru-alpha' else 1 if server == 'ru-bravo' else 2

        mailru_auth = await session.post('https://auth-ac.my.games/social/mailru')
        mailru_state = re.search(r'state=([\d\w]+)', await mailru_auth.text(), re.IGNORECASE).group(1)

        await session.post('https://account.mail.ru')
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
        await session.post('https://auth.mail.ru/cgi-bin/auth', headers=auth_headers, data=data)

        data = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://o2.mail.ru/xlogin',
            'Origin': 'https://o2.mail.ru'
        }
        await session.post(f'https://o2.mail.ru/login?client_id=bbddb88d19b84a62aedd1ffbc71af201&response_type=code&scope=&redirect_uri=https%3A%2F%2Fauth-ac.my.games%2Fsocial%2Fmailru_callback%2F&state={mailru_state}&login={email}', data=data, headers=auth_headers)
        await session.post('https://auth-ac.my.games/sdc?from=https%3A%2F%2Fapi.my.games%2Fsocial%2Fprofile%2Fsession&JSONP_call=callback1522169', data=data, headers=auth_headers)
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
                response = await session.post('https://auth-ac.my.games/auth', headers=payload, data=login_data, allow_redirects=False)
                for i in range(0, 2):
                    response = await session.get(response.headers['location'], allow_redirects=False)
            except:
                continue
            break

    token = session.cookie_jar.filter_cookies('https://api.my.games')
    mc = re.search(r'mc=([\d\w]+)', str(token['mc']), re.IGNORECASE).group(1)
    sdcs = re.search(r'sdcs=([\d\w]+)', str(token['sdcs']), re.IGNORECASE).group(1)

    auth_data = f'<?xml version="1.0" encoding="UTF-8"?><Auth mc="{mc}" sdcs="{sdcs}" ChannelId="{ChannelId}" GcLang="en" UserId="" UserId2=""/>'
    auth_post = await session.post('https://authdl.my.games/gem.php?hint=Auth', data=auth_data, headers=auth_headers)

    auth_code_group = re.search(r'SessionKey="([\d\w]+)"', await auth_post.text(), re.IGNORECASE)

    session_key = auth_code_group.group(1)

    login_data = f'<Login SessionKey="{session_key}" ProjectId="{ProjectId}" ShardId="{ShardId}"/>'
    response_login = await (await session.post('https://authdl.my.games/gem.php?hint=Login', data=login_data, headers=auth_headers)).text()

    account_id = re.search(r'GameAccount="([\d\w]+)"', response_login, re.IGNORECASE).group(1)
    token = re.search(r'Code="([\d\w]+)"', response_login, re.IGNORECASE).group(1)

    return account_id, token


async def main():
    session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=False))
    await my_games(session=session, server="", email="", password="")

    await session.close()


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
