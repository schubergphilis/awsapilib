#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: authentication.py
#
# Copyright 2020 Costas Tyfoxylos
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
Main code for authentication.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""
import json
import logging
import urllib

from copy import deepcopy
from dataclasses import dataclass

import boto3
import botocore
import requests

from bs4 import BeautifulSoup as Bfs

from .authenticationexceptions import NoSigninTokenReceived, InvalidCredentials, ExpiredCredentials

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''11-03-2020'''
__copyright__ = '''Copyright 2020, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''authentication'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

DEFAULT_REGION = 'eu-west-1'


@dataclass
class FilterCookie:
    """Object modeling a cookie for filtering."""

    name: str
    domain: str = ''
    exact_match: bool = False


@dataclass
class CsrfTokenData:
    """Object modeling the data required for csrf token filtering."""

    entity_type: str
    attributes: dict
    attribute_value: str
    headers_name: str


@dataclass
class Domains:
    """Dataclass holding the domains required for authenticating."""

    region: str
    root: str = 'aws.amazon.com'
    sign_in: str = f'signin.{root}'
    console: str = f'console.{root}'

    @property
    def regional_console(self):
        """The domain of the regional console.

        Returns:
            regional_console (str): The regional console domain.

        """
        return f'{self.region}.console.{self.root}'


@dataclass
class Urls:
    """Dataclass holding the urls required for authenticating."""

    region: str
    scheme: str = 'https://'
    root_domain: str = 'aws.amazon.com'
    root: str = f'{scheme}{root_domain}'
    sign_in: str = f'{scheme}signin.{root_domain}'
    console: str = f'{scheme}console.{root_domain}'
    federation: str = f'{sign_in}/federation'

    @property
    def regional_console(self):
        """The url of the regional console.

        Returns:
            regional_console (str): The regional console url.

        """
        return f'{self.scheme}{self.region}.console.{self.root_domain}'

    @property
    def regional_single_sign_on(self):
        """The url of the regional single sign on.

        Returns:
            regional_single_sign_on (str): The regional single sign on url.

        """
        return f'{self.scheme}{self.region}.console.{self.root_domain}/singlesignon'

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


class LoggerMixin:  # pylint: disable=too-few-public-methods
    """Logger."""

    @property
    def logger(self):
        """Exposes the logger to be used by objects using the Mixin.

        Returns:
            logger (logger): The properly named logger.

        """
        return logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')


class Authenticator(LoggerMixin):   # pylint: disable=too-many-instance-attributes
    """Interfaces with aws authentication mechanisms, providing pre signed urls, or authenticated sessions."""

    def __init__(self, arn, session_duration=3600, region=None):
        self.arn = arn
        self.session_duration = session_duration
        self._session = requests.Session()
        self._sts_connection = boto3.client('sts', region_name=region)
        self.region = region or self._get_region()
        self._assumed_role = self._get_assumed_role(arn)
        self.urls = Urls(self.region)
        self.domains = Domains(self.region)

    def _get_region(self):
        region = self._sts_connection._client_config.region_name  # pylint: disable=protected-access
        return region if not region == 'aws-global' else DEFAULT_REGION

    def _get_assumed_role(self, arn):
        self.logger.debug('Trying to assume role "%s".', arn)
        try:
            return self._sts_connection.assume_role(RoleArn=arn,
                                                    RoleSessionName="AssumeRoleSession",
                                                    DurationSeconds=self.session_duration)
        except botocore.exceptions.ParamValidationError as error:
            raise ValueError('The arn you provided is incorrect: {}'.format(error)) from None
        except (botocore.exceptions.NoCredentialsError, botocore.exceptions.ClientError) as error:
            raise InvalidCredentials(error) from None

    @property
    def session_credentials(self):
        """Valid credentials for a session.

        Returns:
            credentials (dict): A properly structured dictionary of session credentials.

        """
        payload = {'sessionId': 'AccessKeyId',
                   'sessionKey': 'SecretAccessKey',
                   'sessionToken': 'SessionToken'}
        return self._get_credentials(payload)

    @property
    def assumed_role_credentials(self):
        """Valid credentials for an assumed session.

        Returns:
            credentials (dict): A properly structured dictionary of an assumed session credentials.

        """
        payload = {'aws_access_key_id': 'AccessKeyId',
                   'aws_secret_access_key': 'SecretAccessKey',
                   'aws_session_token': 'SessionToken'}
        return self._get_credentials(payload)

    def _get_credentials(self, payload):
        self.logger.debug('Getting credentials from assumed role object.')
        credentials = self._assumed_role.get('Credentials')
        self.logger.debug('Building payload.')
        payload_ = {key: credentials.get(value)
                    for key, value in payload.items()}
        return payload_

    def _get_signin_token(self):  # we can pass a duration here.
        self.logger.debug('Trying to get signin token.')
        params = {'Action': 'getSigninToken',
                  # 'SessionDuration': str(duration),
                  'Session': json.dumps(self.session_credentials)}
        response = requests.get(self.urls.federation, params=params)
        if all([response.status_code == 401, response.text == 'Token Expired']):
            try:
                self._assumed_role = self._get_assumed_role(self.arn)
                return self._get_signin_token()
            except InvalidCredentials:
                self.logger.error('The credentials on the environment do not provide access for session refresh.')
                raise
        if response.ok:
            return response.json().get('SigninToken')
        raise NoSigninTokenReceived(response.status_code, response.text)

    def get_signed_url(self, domain='Example.com', destination=None):
        """Returns a pre signed url that is authenticated.

        Args:
            domain (str): The domain to request the session as.
            destination (str): The service to redirect to after successful redirection.


        Returns:
            url (str): An authenticated pre signed url.

        """
        params = {'Action': 'login',
                  'Issuer': domain,
                  'Destination': destination or self.urls.console,
                  'SigninToken': self._get_signin_token()}
        return f'{self.urls.federation}?{urllib.parse.urlencode(params)}'

    @staticmethod
    def _filter_cookies(cookies, filters=None):
        result_cookies = []
        for filter_ in filters:
            for cookie in cookies:
                conditions = [cookie.name == filter_.name]
                if filter_.exact_match:
                    conditions.extend([filter_.domain == f'{cookie.domain}{cookie.path}'])
                elif filter_.domain:
                    conditions.extend([filter_.domain in f'{cookie.domain}{cookie.path}'])
                if all(conditions):
                    result_cookies.append(cookie)
        return result_cookies

    @staticmethod
    def _cookies_to_dict(cookies):
        return {cookie.name: cookie.value for cookie in cookies}

    @staticmethod
    def _header_cookie_from_cookies(cookies):
        return '; '.join([f'{key}={value}'
                          for key, value in Authenticator._cookies_to_dict(cookies).items()])

    @property
    def _default_headers(self):
        return deepcopy({'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                         'Accept-Encoding': 'gzip, deflate, br',
                         'Accept-Language': 'en-US,en;q=0.5',
                         'Connection': 'keep-alive',
                         'Upgrade-Insecure-Requests': '1',
                         'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:73.0) '
                                       'Gecko/20100101 Firefox/73.0'})

    @property
    def _standard_cookies(self):
        return [FilterCookie('aws-account-data'),
                FilterCookie('aws-ubid-main'),
                FilterCookie('aws-userInfo'),
                FilterCookie('awsc-actm'),
                FilterCookie('awsm-vid')]

    def _get_response(self, url, params=None, extra_cookies=None, headers=None):
        extra_cookies = extra_cookies or []
        headers = headers or {}
        cookies_to_filter = self._standard_cookies + extra_cookies
        headers.update(self._default_headers)
        cookies = self._filter_cookies(self._session.cookies, cookies_to_filter)
        headers['Cookie'] = self._header_cookie_from_cookies(cookies)
        arguments = {'url': url,
                     'headers': headers,
                     'cookies': self._cookies_to_dict(cookies),
                     'allow_redirects': False}
        if params:
            arguments.update({'params': params})
        self.logger.debug('Getting url :%s with arguments : %s', url, arguments)
        response = requests.get(**arguments)
        if not response.ok:
            try:
                error_response = Bfs(response.text, features='html.parser')
                error_title = error_response.title.string.strip()
                err_msg = error_response.find('div', {'id': 'content'}).find('p').string
            except AttributeError:
                raise ValueError('Response received: %s' % response.text)
            if all([response.status_code == 400, error_title == 'Credentials expired']):
                raise ExpiredCredentials(response.status_code, err_msg)
            raise ValueError('Response received: %s' % response.text)
        self._debug_response(response, cookies)
        self._session.cookies.update(response.cookies)
        return response

    @staticmethod
    def _query_to_params(query):
        query_lines = query.split('&') if query else []
        return {line.split('=')[0]: line.split('=')[1] for line in query_lines}

    def _debug_response(self, response, cookies):
        params = self._query_to_params(urllib.parse.urlparse(response.request.url)[4])
        self.logger.debug('URL : %s', response.request.url)
        if params:
            self.logger.debug('Params : ')
            for key, value in params.items():
                self.logger.debug('\t%s : %s', key, value)
        self.logger.debug('Response status : %s', response.status_code)
        self.logger.debug('\tRequest Headers :')
        for name, value in dict(sorted(response.request.headers.items(), key=lambda x: x[0].lower())).items():
            self.logger.debug('\t\t%s : %s', name, value)
        self.logger.debug('\tRequest Cookies :')
        for cookie in sorted(cookies, key=lambda x: x.name.lower()):
            self.logger.debug('\t\t%s (domain:%s) : %s', cookie.name, cookie.domain, cookie.value)
        self.logger.debug('\tResponse Headers :')
        for name, value in dict(sorted(response.headers.items(), key=lambda x: x[0].lower())).items():
            self.logger.debug('\t\t%s : %s', name, value)
        self.logger.debug('\tResponse Cookies :')
        for name, value in dict(sorted(response.cookies.items(), key=lambda x: x[0].lower())).items():
            self.logger.debug('\t\t%s : %s', name, value)
        self.logger.debug('Session Cookies :')
        for cookie in sorted(self._session.cookies, key=lambda x: x.name.lower()):
            self.logger.debug('\t%s (domain:%s%s) : %s', cookie.name, cookie.domain, cookie.path, cookie.value)

    def get_control_tower_authenticated_session(self):
        """Authenticates to control tower and returns an authenticated session.

        Returns:
            session (requests.Session): An authenticated session with headers and cookies set.

        """
        service = 'controltower'
        self._session.get(self.get_signed_url())
        url = f'{self.urls.regional_console}/{service}/home'
        host = urllib.parse.urlparse(url)[1]
        self.logger.debug('Setting host to: %s', host)
        self._get_response(url,
                           params={'region': self.region},
                           extra_cookies=[FilterCookie('JSESSIONID'),
                                          FilterCookie('aws-userInfo-signed')])
        hash_args = self._get_response(url,
                                       params={'state': 'hashArgs#'},
                                       extra_cookies=[FilterCookie('JSESSIONID', self.urls.regional_console),
                                                      FilterCookie('aws-userInfo-signed',),
                                                      FilterCookie('aws-creds-code-verifier', self.urls.regional_console
                                                                   )])
        oauth = self._get_response(hash_args.headers.get('Location'),
                                   extra_cookies=[FilterCookie('JSESSIONID', self.urls.regional_console),
                                                  FilterCookie('aws-creds', self.domains.sign_in),
                                                  FilterCookie('aws-userInfo-signed', ),
                                                  FilterCookie('aws-creds-code-verifier', f'/{service}')],)
        oauth_challenge = self._get_response(oauth.headers.get('Location'),
                                             extra_cookies=[FilterCookie('JSESSIONID', self.urls.regional_console),
                                                            FilterCookie('aws-userInfo-signed',),
                                                            FilterCookie('aws-creds', self.domains.sign_in),
                                                            FilterCookie('aws-creds-code-verifier', f'/{service}')])
        self._get_response(oauth_challenge.headers.get('Location'),
                           extra_cookies=[FilterCookie('aws-creds', f'/{service}'),
                                          FilterCookie('JSESSIONID', host),
                                          FilterCookie('aws-userInfo-signed')])
        dashboard = self._get_response(url,
                                       params={'region': self.region},
                                       extra_cookies=[FilterCookie('aws-creds', f'/{service}'),
                                                      FilterCookie('JSESSIONID', host),
                                                      FilterCookie('aws-consoleInfo'),
                                                      FilterCookie('aws-userInfo-signed')])
        csrf_token_data = CsrfTokenData('meta', {'name': 'awsc-csrf-token'}, 'content', 'X-CSRF-TOKEN')
        extra_cookies = [FilterCookie('JSESSIONID', self.domains.regional_console),
                         FilterCookie('aws-creds', f'{self.domains.regional_console}/{service}')]
        return self._get_session_from_console(dashboard, csrf_token_data, extra_cookies)

    def get_sso_authenticated_session(self):
        """Authenticates to Single Sign On and returns an authenticated session.

        Returns:
            session (requests.Session): An authenticated session with headers and cookies set.

        """
        service = 'singlesignon'
        url = f'{self.urls.regional_console}/{service}/home?region={self.region}#/dashboard'
        self._get_response(self.get_signed_url())
        host = urllib.parse.urlparse(url)[1]
        self.logger.debug('Setting host to: %s', host)
        self._get_response(url, extra_cookies=[FilterCookie('JSESSIONID', f'/{service}')])
        hash_args = self._get_response(url,
                                       params={'state': 'hashArgs#'},
                                       extra_cookies=[FilterCookie('JSESSIONID', f'/{service}'),
                                                      FilterCookie('aws-userInfo-signed', )])
        oauth = self._get_response(hash_args.headers.get('Location'),
                                   extra_cookies=[FilterCookie('aws-creds', self.domains.sign_in),
                                                  FilterCookie('aws-userInfo-signed', )])
        oauth_challenge = self._get_response(oauth.headers.get('Location'),
                                             extra_cookies=[FilterCookie('JSESSIONID', self.urls.regional_console),
                                                            FilterCookie('aws-userInfo-signed', ),
                                                            FilterCookie('aws-creds-code-verifier', f'/{service}')
                                                            ])
        dashboard = self._get_response(oauth_challenge.headers.get('Location'),
                                       extra_cookies=[FilterCookie('aws-creds', f'/{service}'),
                                                      FilterCookie('JSESSIONID', host)])
        csrf_token_data = CsrfTokenData('meta', {'name': 'awsc-csrf-token'}, 'content', 'X-CSRF-TOKEN')
        extra_cookies = [FilterCookie('JSESSIONID', self.domains.regional_console),
                         FilterCookie('aws-creds', f'{self.domains.regional_console}/{service}')]
        return self._get_session_from_console(dashboard, csrf_token_data, extra_cookies)

    def get_billing_authenticated_session(self):
        """Authenticates to billing and returns an authenticated session.

        Returns:
            session (requests.Session): An authenticated session with headers and cookies set.

        """
        service = 'billing'
        url = f'{self.urls.console}/{service}/home?region={self.region}'
        self._get_response(self.get_signed_url())
        host = urllib.parse.urlparse(url)[1]
        self.logger.debug('Setting host to: %s', host)
        self._get_response(url, extra_cookies=[FilterCookie('JSESSIONID', f'/{service}'),
                                               FilterCookie('aws-userInfo-signed', )])
        hash_args = self._get_response(url,
                                       params={'state': 'hashArgs#'},
                                       extra_cookies=[FilterCookie('JSESSIONID', f'/{service}'),
                                                      FilterCookie('aws-userInfo-signed', ),
                                                      FilterCookie('aws-creds-code-verifier', f'/{service}')])
        oauth = self._get_response(hash_args.headers.get('Location'),
                                   extra_cookies=[FilterCookie('aws-creds', self.domains.sign_in),
                                                  FilterCookie('aws-userInfo-signed', )])
        oauth_challenge = self._get_response(oauth.headers.get('Location'),
                                             extra_cookies=[FilterCookie('JSESSIONID', self.urls.regional_console),
                                                            FilterCookie('aws-userInfo-signed', ),
                                                            FilterCookie('aws-creds-code-verifier', f'/{service}')
                                                            ])
        dashboard = self._get_response(oauth_challenge.headers.get('Location'),
                                       extra_cookies=[FilterCookie('aws-creds', f'/{service}'),
                                                      FilterCookie('JSESSIONID', host)])
        csrf_token_data = CsrfTokenData('input', {'id': 'xsrfToken'}, 'value', 'x-awsbc-xsrf-token')
        extra_cookies = [FilterCookie('aws-creds', '/billing')]
        return self._get_session_from_console(dashboard, csrf_token_data, extra_cookies)

    def _get_session_from_console(self, console_page_response, csrf_token_data, extra_cookies=None):
        soup = Bfs(console_page_response.text, features='html.parser')
        try:
            csrf_token = soup.find(csrf_token_data.entity_type,
                                   csrf_token_data.attributes).attrs.get(csrf_token_data.attribute_value)
        except AttributeError:
            raise ValueError('Response received: %s' % console_page_response.text)
        if not csrf_token:
            raise NoSigninTokenReceived('Unable to retrieve csrf token.')
        session = requests.Session()
        cookies_to_filter = self._standard_cookies + extra_cookies if extra_cookies else []
        cookies = self._filter_cookies(self._session.cookies, cookies_to_filter)
        session.headers.update(self._default_headers)
        session.headers.update({'Cookie': self._header_cookie_from_cookies(cookies),
                                csrf_token_data.headers_name: csrf_token})
        for cookie in cookies:
            session.cookies.set_cookie(cookie)
        return session
