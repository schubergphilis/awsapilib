#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsapilib.py
#
# Copyright 2021 Costas Tyfoxylos
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Main code for awsapilib.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import logging
import urllib
from dataclasses import dataclass
from random import choice

from bs4 import BeautifulSoup as Bfs
from fake_useragent import UserAgent
from requests import Session, Request

from .awsapilibexceptions import (NoSigninTokenReceived,
                                  ExpiredCredentials,
                                  UnexpectedResponse)

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = 'google'
__date__ = '21-08-2023'
__copyright__ = 'Copyright 2023, Costas Tyfoxylos'
__credits__ = ["Costas Tyfoxylos"]
__license__ = 'MIT'
__maintainer__ = 'Costas Tyfoxylos'
__email__ = '<ctyfoxylos@schubergphilis.com>'
__status__ = 'Development'  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = __name__
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

RANDOM_USER_AGENT = UserAgent(browsers=['firefox', 'chrome'],
                              os=choice(['macos', 'windows']),
                              min_percentage=5.0).random


class LoggerMixin:
    """Logger."""

    @property
    def logger(self):
        """Exposes the logger to be used by objects using the Mixin.

        Returns:
            logger (logger): The properly named logger.

        """
        return logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')


@dataclass
class Urls:
    """Dataclass holding the urls required for authenticating."""

    region: str
    scheme: str = 'https://'
    root_domain: str = 'aws.amazon.com'
    root: str = f'{scheme}{root_domain}'
    sign_in: str = f'{scheme}signin.{root_domain}'
    console: str = f'{scheme}console.{root_domain}'
    console_home: str = f'{scheme}console.{root_domain}/console/home'
    billing_home: str = f'{scheme}console.{root_domain}/billing/home'
    billing_rest: str = f'{scheme}us-east-1.console.{root_domain}/billing/rest'
    billing_home_account: str = f'{billing_home}#/account'
    iam_home: str = f'{scheme}console.{root_domain}/iam/home'
    iam_home_use2: str = f'{iam_home}?region=us-east-2'
    iam_api: str = f'{scheme}console.{root_domain}/iam/api'
    federation: str = f'{sign_in}/federation'
    mfa: str = f'{sign_in}/mfa'
    signing_service: str = f'{sign_in}/signin'
    oauth_service: str = f'{sign_in}/oauth'
    password_reset: str = f'{sign_in}/resetpassword'
    account_update: str = f'{sign_in}/updateaccount'
    global_billing_home: str = f'{scheme}us-east-1.console.{root_domain}/billing/home'
    global_iam_home: str = f'{scheme}us-east-1.console.{root_domain}/iam/home'
    account_management: str = f'{billing_rest}/v1.0/account'

    @property
    def regional_console(self):
        """The url of the regional console.

        Returns:
            regional_console (str): The regional console url.

        """
        return f'{self.scheme}{self.region}.console.{self.root_domain}'

    @property
    def regional_console_home(self):
        """The url of the regional console home page.

        Returns:
            regional_console (str): The regional console home page url.

        """
        return f'{self.scheme}{self.region}.console.{self.root_domain}/console/home'

    @property
    def regional_single_sign_on(self):
        """The url of the regional single sign on.

        Returns:
            regional_single_sign_on (str): The regional single sign on url.

        """
        return f'{self.scheme}{self.region}.console.{self.root_domain}/singlesignon'

    @property
    def regional_single_sign_on_home(self):
        """The url of the regional single sign on home page.

        Returns:
            regional_single_sign_on_home (str): The regional single sign on home page url.

        """
        return f'{self.regional_single_sign_on}/home'

    @property
    def regional_control_tower(self):
        """The url of the regional control tower service.

        Returns:
            regional_control_tower (str): The regional control tower on url.

        """
        return f'{self.scheme}{self.region}.console.{self.root_domain}/controltower'

    @property
    def regional_relay_state(self):
        """The regional relay state url.

        Returns:
            relay_state (str): The regional relay state url.

        """
        return f'{self.regional_console}home?region={self.region}#'

    @property
    def regional_cloudformation(self):
        """The url of the regional cloudformation service.

        Returns:
            regional_cloud_formation (str): The regional cloudformation url.

        """
        return f'{self.scheme}{self.region}.console.{self.root_domain}/cloudformation'

    @property
    def regional_cloudformation_home(self):
        """The url of the regional cloudformation home service.

        Returns:
            regional_cloud_formation (str): The regional cloudformation home url.

        """
        return f'{self.regional_cloudformation}/home'


DEFAULT_REGION = 'eu-west-1'
REQUEST_TIMEOUT_IN_SECONDS = 5


@dataclass
class CsrfTokenData:
    """Object modeling the data required for csrf token filtering."""

    entity_type: str
    attributes: dict
    attribute_value: str
    headers_name: str


class AwsSession(Session):

    def __init__(self, timeout=REQUEST_TIMEOUT_IN_SECONDS, allow_redirects=True):
        super().__init__()
        self.timeout = timeout
        self.allow_redirects = allow_redirects

    def request(self,  # noqa
                method,
                url,
                params=None,
                data=None,
                headers=None,
                cookies=None,
                files=None,
                auth=None,
                timeout=None,
                allow_redirects=True,
                proxies=None,
                hooks=None,
                stream=None,
                verify=None,
                cert=None,
                json=None):
        """Constructs a :class:`Request <Request>`, prepares it and sends it.

        Returns :class:`Response <Response>` object.

        :param method: method for the new :class:`Request` object.
        :param url: URL for the new :class:`Request` object.
        :param params: (optional) Dictionary or bytes to be sent in the query
            string for the :class:`Request`.
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
            object to send in the body of the :class:`Request`.
        :param json: (optional) json to send in the body of the
            :class:`Request`.
        :param headers: (optional) Dictionary of HTTP Headers to send with the
            :class:`Request`.
        :param cookies: (optional) Dict or CookieJar object to send with the
            :class:`Request`.
        :param files: (optional) Dictionary of ``'filename': file-like-objects``
            for multipart encoding upload.
        :param auth: (optional) Auth tuple or callable to enable
            Basic/Digest/Custom HTTP Auth.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple
        :param allow_redirects: (optional) Set to True by default.
        :type allow_redirects: bool
        :param proxies: (optional) Dictionary mapping protocol or protocol and
            hostname to the URL of the proxy.
        :param stream: (optional) whether to immediately download the response
            content. Defaults to ``False``.
        :param verify: (optional) Either a boolean, in which case it controls whether we verify
            the server's TLS certificate, or a string, in which case it must be a path
            to a CA bundle to use. Defaults to ``True``. When set to
            ``False``, requests will accept any TLS certificate presented by
            the server, and will ignore hostname mismatches and/or expired
            certificates, which will make your application vulnerable to
            man-in-the-middle (MitM) attacks. Setting verify to ``False``
            may be useful during local development or testing.
        :param cert: (optional) if String, path to ssl client cert file (.pem).
            If Tuple, ('cert', 'key') pair.
        :rtype: requests.Response
        """
        headers = headers or {}
        headers.update({'User-Agent': RANDOM_USER_AGENT})
        # Create the Request.
        req = Request(
            method=method.upper(),
            url=url,
            headers=headers,
            files=files,
            data=data or {},
            json=json,
            params=params or {},
            auth=auth,
            cookies=cookies,
            hooks=hooks,
        )
        prep = self.prepare_request(req)

        proxies = proxies or {}

        settings = self.merge_environment_settings(
            prep.url, proxies, stream, verify, cert
        )

        # Send the request.
        send_kwargs = {
            "timeout": self.timeout,
            "allow_redirects": self.allow_redirects,
        }
        send_kwargs.update(settings)
        resp = self.send(prep, **send_kwargs)
        if not resp.ok:
            try:
                error_response = Bfs(resp.text, features='html.parser')
                error_title = error_response.title.string.strip()
                err_msg = error_response.find('div', {'id': 'content'}).find('p').string
            except AttributeError:
                raise UnexpectedResponse(f'Response received: {resp.text}') from None
            if all([resp.status_code == 400, error_title == 'Credentials expired']):
                raise ExpiredCredentials(resp.status_code, err_msg)
            raise UnexpectedResponse(f'Response received: {resp.text}') from None
        AwsSession._debug_response(resp, req.cookies, self)
        LOGGER.debug(f'Response received: {resp.text} with status code {resp.status_code}.')
        return resp

    @staticmethod
    def _debug_response(response, cookies, session):
        cookies = cookies or []
        query = urllib.parse.urlparse(response.request.url)[4]
        query_lines = query.split('&') if query else []
        params = {line.split('=')[0]: line.split('=')[1] for line in query_lines}
        LOGGER.debug('URL : %s', response.request.url)
        if params:
            LOGGER.debug('Params : ')
            for key, value in params.items():
                LOGGER.debug('\t%s : %s', key, value)
        LOGGER.debug('Response status : %s', response.status_code)
        LOGGER.debug('\tRequest Headers :')
        for name, value in dict(sorted(response.request.headers.items(), key=lambda x: x[0].lower())).items():
            LOGGER.debug('\t\t%s : %s', name, value)
        LOGGER.debug('\tRequest Cookies :')
        for cookie in sorted(cookies, key=lambda x: x.name.lower()):
            LOGGER.debug('\t\t%s (domain:%s) : %s', cookie.name, cookie.domain, cookie.value)
        LOGGER.debug('\tResponse Headers :')
        for name, value in dict(sorted(response.headers.items(), key=lambda x: x[0].lower())).items():
            LOGGER.debug('\t\t%s : %s', name, value)
        LOGGER.debug('\tResponse Cookies :')
        for name, value in dict(sorted(response.cookies.items(), key=lambda x: x[0].lower())).items():
            LOGGER.debug('\t\t%s : %s', name, value)
        LOGGER.debug('Session Cookies :')
        for cookie in sorted(session.cookies, key=lambda x: x.name.lower()):
            LOGGER.debug('\t%s (domain:%s%s) : %s', cookie.name, cookie.domain, cookie.path, cookie.value)

    def get_console_session(self, console_page_response, csrf_token_data, token_transform=lambda x: x):
        soup = Bfs(console_page_response.text, features='html.parser')
        try:
            csrf_token = soup.find(csrf_token_data.entity_type,
                                   csrf_token_data.attributes).attrs.get(csrf_token_data.attribute_value)
        except AttributeError:
            raise UnexpectedResponse(f'Response received: {console_page_response.text}') from None
        if not csrf_token:
            raise NoSigninTokenReceived('Unable to retrieve csrf token.')
        self.headers.update({csrf_token_data.headers_name: token_transform(csrf_token)})
        return self
