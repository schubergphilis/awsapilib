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
   https://google.github.io/styleguide/pyguide.html

"""
import json
import logging
import os
import urllib
from dataclasses import asdict
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse

import boto3
import botocore
import requests
from boto3_type_annotations.sts import Client as StsClient
from bs4 import BeautifulSoup as Bfs
from pyotp import TOTP
from requests import Session, Request

from awsapilib.awsapilib import RANDOM_USER_AGENT, LoggerMixin, Urls
from awsapilib.captcha import Solver, Terminal, Iterm
from .metadata import MetadataManager
from .authenticationexceptions import (InvalidArn,
                                       NoSigninTokenReceived,
                                       ExpiredCredentials,
                                       InvalidCredentials,
                                       UnexpectedResponse,
                                       NotSolverInstance, UnableToQueryMFA, NoMFAProvided, UnsupportedMFA,
                                       InvalidAuthentication, ServerError, InvalidCaptcha, UnableToResolveAccount)

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
LOGGER_BASENAME = __name__
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

CONSOLE_SOLVER = Iterm if 'iterm' in os.environ.get('TERM_PROGRAM', '').lower() else Terminal


@dataclass
class Captcha:
    """Models a Captcha."""

    url: str
    token: str
    obfuscation_token: str


@dataclass
class Oidc:
    """Models an OIDC response."""

    client_id: str
    code_challenge: str
    code_challenge_method: str
    redirect_uri: str

    @property
    def data(self):
        return asdict(self)


@dataclass
class XAmz:
    """Models an X-Amz response."""

    security_token: str
    date: str
    algorithm: str
    credential: str
    signed_headers: str
    signature: str

    @property
    def data(self):
        return {'X-Amz-Security-Token': self.security_token,
                'X-Amz-Date': self.date,
                'X-Amz-Algorithm': self.algorithm,
                'X-Amz-Credential': self.credential,
                'X-Amz-SignedHeaders': self.signed_headers,
                'X-Amz-Signature': self.signature}


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
        self.headers.update({'User-Agent': RANDOM_USER_AGENT})
        self.x_amz_info = None

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


class RootAuthenticator(LoggerMixin):
    """Manages accounts password lifecycles and can provide a root console session."""

    def __init__(self, solver=CONSOLE_SOLVER, user_agent=RANDOM_USER_AGENT):
        self._solver = solver()
        if not isinstance(self._solver, Solver):
            raise NotSolverInstance
        self.user_agent = user_agent
        self.metadata_manager = MetadataManager(self.user_agent)

    @staticmethod
    def _get_mfa_type(session, email):
        """Gets the MFA type of the account.

        Args:
            email: The email of the account to check for MFA settings.

        Returns:
            The type of MFA set (only "SW" currently supported) None if no MFA is set.

        """
        payload = {'email': email,
                   'csrf': session.cookies.get('aws-signin-csrf', path='/signin'),
                   'redirect_uri': f'{Urls.console_home}?'
                                   f'fromtb=true&'
                                   f'hashArgs=%23&'
                                   f'isauthcode=true&'
                                   f'state=hashArgsFromTB_us-east-1_4d16544228963f5b'
                   }
        response = session.post(Urls.mfa, data=payload)
        if not response.ok:
            raise UnableToQueryMFA(f'Unsuccessful response received: {response.text} '
                                   f'with status code: {response.status_code}')
        LOGGER.debug(f'Received response {response.text} with status code {response.status_code}')
        mfa_type = response.json().get('mfaType')
        return None if mfa_type == 'NONE' else mfa_type

    @staticmethod
    def _validate_mfa_type(session, email, mfa_serial):
        mfa_type = RootAuthenticator._get_mfa_type(session, email)
        if mfa_type:
            if not mfa_serial:
                raise NoMFAProvided(f'Account with email "{email}" is protected by mfa type "{mfa_type}" but no serial '
                                    f'was provided.\n Please provide the initial serial that was used to setup MFA.')
            if mfa_type != 'SW':
                raise UnsupportedMFA('Currently on SW mfa type is supported.')
        return mfa_type

    @staticmethod
    def _get_root_login_parameters(metadata_manager,  # pylint: disable=too-many-arguments
                                   email,
                                   csrf_token,
                                   session_id,
                                   challenge_redirect,
                                   password,
                                   mfa_type,
                                   mfa_serial):
        code_challenge = next((entry[1] for entry in parse_qsl(urlparse(challenge_redirect).query)
                               if entry[0] == 'code_challenge'))
        parameters = {'action': 'authenticateRoot',
                      'email': email,
                      'password': password,
                      'redirect_uri': 'https://console.aws.amazon.com/console/home?hashArgs=%23&isauthcode=true&'
                                      'nc2=h_ct&src=header-signin&state=hashArgsFromTB_eu-north-1_f4f70b834bfa25f4',
                      'client_id': 'arn:aws:signin:::console/canvas',
                      'csrf': csrf_token,
                      'sessionId': session_id,
                      'metadata1': metadata_manager.get_random_metadata(challenge_redirect),
                      'rememberMfa': False,
                      'code_challenge': code_challenge,
                      'code_challenge_method': 'SHA-256',
                      'mfaSerial': ''}
        if mfa_type:
            totp = TOTP(mfa_serial)
            parameters.update({'mfaType': mfa_type,
                               'mfa1': totp.now()})
        return parameters

    # pylint: disable=too-many-locals
    @staticmethod
    def get_root_console_session(solver, metadata_manager, email, password, mfa_serial=None):
        session = AwsSession()
        csrf_token, session_id, challenge_redirect, oauth_redirect = RootAuthenticator.parse_home_page_redirects(
            session)
        mfa_type = RootAuthenticator._validate_mfa_type(session, email, mfa_serial)
        arguments = {'metadata_manager': metadata_manager,
                     'email': email,
                     'csrf_token': csrf_token,
                     'session_id': session_id,
                     'challenge_redirect': challenge_redirect}
        RootAuthenticator.resolve_account_type(session=session,
                                               **arguments,
                                               oauth_redirect=oauth_redirect,
                                               solver=solver)
        parameters = RootAuthenticator._get_root_login_parameters(**arguments,
                                                                  password=password,
                                                                  mfa_type=mfa_type,
                                                                  mfa_serial=mfa_serial)
        headers = {'X-Requested-With': 'XMLHttpRequest',
                   'Referer': challenge_redirect}
        count = 0
        while True:
            count += 1
            LOGGER.debug(f'Connecting to url {Urls.signing_service} with data: {parameters} and headers:{headers}')
            response = session.post(Urls.signing_service, data=parameters, headers=headers)
            success = RootAuthenticator.validate_response(response)
            if all([success, response.json().get('properties', {}).get('CaptchaURL') is not None]):
                response = RootAuthenticator._process_after_login_captcha(solver, session, parameters, response)
                success = RootAuthenticator.validate_response(response)
            redirect = response.json().get('properties', {}).get('RedirectTo')
            if any([redirect, count == 3]):
                break
        if not all([success, redirect is not None]):
            LOGGER.error(f'Found an unexpected redirect {redirect}.')
            raise InvalidAuthentication(f'Unable to authenticate, response received was: {response.text} '
                                        f'with status code: {response.status_code}')
        response = session.get(redirect)
        if not response.ok:
            LOGGER.error(f'Received broken response: {response.text}')
            raise InvalidAuthentication('Unable to get a valid authenticated session for root console.')
        return session

    def get_billing_root_session(self, email, password, mfa_serial=None):
        """Retrieves a root user billing session.

        Args:
            email (str): The email of the root user.
            password (str): The password of the root user.
            mfa_serial (str): The mfa seed if mfa is set.

        Returns:
            session (Session): A valid session.

        """
        session = RootAuthenticator.get_root_console_session(self._solver,
                                                             self.metadata_manager,
                                                             email,
                                                             password,
                                                             mfa_serial)
        session.get(Urls.billing_home)
        session.allow_redirects = False
        hash_args = session.get(Urls.billing_home, params={'state': 'hashArgs#'})
        session.get(hash_args.headers.get('Location'))
        session.allow_redirects = True
        dashboard = session.get(Urls.global_billing_home,
                                params={'state': 'hashArgs#', 'skipRegion': 'true',
                                        'region': 'us-east-1'})
        csrf_token_data = CsrfTokenData(entity_type='input',
                                        attributes={'id': 'xsrfToken'},
                                        attribute_value='value',
                                        headers_name='x-awsbc-xsrf-token')

        return session.get_console_session(dashboard, csrf_token_data)

    def get_iam_root_session(self, email, password, mfa_serial=None):
        """Retrieves an iam console session, filtered with specific cookies or not depending on the usage.

        Args:
            email (str): The email of the root user.
            password (str): The password of the root user.
            mfa_serial (str): The mfa seed if mfa is set.

        Returns:
            session (Session): A valid session.

        """
        session = RootAuthenticator.get_root_console_session(self._solver,
                                                             self.metadata_manager,
                                                             email,
                                                             password,
                                                             mfa_serial)
        session.get(Urls.iam_home_use2)
        session.allow_redirects = False
        hash_args = session.get(Urls.iam_home_use2, params={'state': 'hashArgs#'})
        session.get(hash_args.headers.get('Location'))
        session.allow_redirects = True
        dashboard = session.get(Urls.global_iam_home,
                                params={'state': 'hashArgs#', 'skipRegion': 'true',
                                        'region': 'us-east-1'})
        csrf_token_data = CsrfTokenData(entity_type='meta',
                                        attributes={'id': 'xsrf-token'},
                                        attribute_value='data-token',
                                        headers_name='X-CSRF-TOKEN')
        return session.get_console_session(dashboard, csrf_token_data)

    @staticmethod
    def parse_home_page_redirects(session):
        for url in [Urls.root, Urls.console_home]:
            LOGGER.debug(f'Trying to get {url} for all initial cookies.')
            session.get(url)
        # TODO error checking.
        params = {'nc2': 'h_ct',
                  'src': 'header-signin',
                  'hashArgs': '%23'}
        response = session.get(f'{Urls.console_home}', params=params)
        if not response.ok:
            LOGGER.debug(
                f'Request failed with response status: {response.status_code} and text: {response.content}')
            raise ServerError('Unable to get initial pages!')
        soup = Bfs(response.text, features='html.parser')
        session_id = soup.find('meta', {'name': 'session_id'}).get('content')
        csrf_token = soup.find('meta', {'name': 'csrf_token'}).get('content')
        oauth_redirect = response.history[-3].headers.get('Location')
        challenge_redirect = response.history[-1].headers.get('Location')
        return csrf_token, session_id, challenge_redirect, oauth_redirect

    @staticmethod
    def get_captcha_info(response):
        try:
            properties = response.json().get('properties', {})
            url = properties.get('CaptchaURL')
            captcha_token = properties.get('CES')
            captcha_obfuscation_token = properties.get('captchaObfuscationToken')
            return Captcha(url, captcha_token, captcha_obfuscation_token)
        except ValueError:
            raise InvalidAuthentication(response.text) from None

    @staticmethod
    def get_x_amz_info(url):
        parsed_query = dict(urllib.parse.parse_qsl(url))
        return XAmz(parsed_query.get('X-Amz-Security-Token'),
                    parsed_query.get('X-Amz-Date'),
                    parsed_query.get('X-Amz-Algorithm'),
                    parsed_query.get('X-Amz-Credential'),
                    parsed_query.get('X-Amz-SignedHeaders'),
                    parsed_query.get('X-Amz-Signature'))

    @staticmethod
    def update_parameters_with_captcha(solver, parameters, response):
        captcha = RootAuthenticator.get_captcha_info(response)
        parameters.update({'captcha_guess': solver.solve(captcha.url),
                           'captcha_token': captcha.token,
                           'captchaObfuscationToken': captcha.obfuscation_token})
        return parameters

    @staticmethod
    def validate_response(response):
        if not response.ok:
            LOGGER.debug(f'Response failed with text: {response.text} and status code {response.status_code}')
            return False
        try:
            success = any([response.json().get('state', '') == 'SUCCESS',
                           response.json().get('properties', {}).get('CaptchaURL')])
            if response.json().get('properties', {}).get('recovery_result', '') == 'wrong_captcha':
                raise InvalidCaptcha(response.json())
            if response.json().get('properties', {}).get('Title', '') == 'Authentication failed':
                raise InvalidAuthentication(response.json())
        except AttributeError:
            LOGGER.debug(f'Response failed with text: {response.text} and status code {response.status_code}')
            success = False
        return success

    # pylint: disable=too-many-arguments,unused-argument
    @staticmethod
    def resolve_account_type(session,
                             metadata_manager,
                             email,
                             csrf_token,
                             session_id,
                             challenge_redirect,
                             oauth_redirect,
                             solver):
        response = RootAuthenticator.resolve_account_type_response(**locals())
        success = RootAuthenticator.validate_response(response)
        if not success:
            raise UnableToResolveAccount(f'Failed to resolve account type with response: {response.text} '
                                         f'and status code {response.status_code}')
        LOGGER.debug(f'Resolved account type successfully with response :{response.text}')
        return success

    @staticmethod
    def resolve_account_type_response(session,
                                      metadata_manager,
                                      email,
                                      csrf_token,
                                      session_id,
                                      challenge_redirect,
                                      oauth_redirect,
                                      solver):
        parameters = {'action': 'resolveAccountType',
                      'redirect_uri': challenge_redirect,
                      'email': email,
                      'metadata1': metadata_manager.get_random_metadata(oauth_redirect),
                      'csrf': csrf_token,
                      'sessionId': session_id}
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        response = session.post(Urls.signing_service, data=parameters, headers=headers)
        LOGGER.debug(f'Received response {response.text} with status code {response.status_code}')
        if not response.ok:
            LOGGER.warning(f'Request failed with response: {response.text} and status: {response.status_code}')
        if response.json().get('properties', {}).get('CaptchaURL') is None:
            LOGGER.debug('No Captcha information found.')
            return response
        LOGGER.debug('Getting the resolve account type captcha.')
        LOGGER.debug(f'Received response {response.text} with status code {response.status_code}')
        parameters = RootAuthenticator.update_parameters_with_captcha(solver, parameters, response)
        return session.post(Urls.signing_service, data=parameters, headers=headers)

    @staticmethod
    def _process_after_login_captcha(solver, session, parameters, response):
        LOGGER.debug('Getting the after login type captcha.')
        parameters = RootAuthenticator.update_parameters_with_captcha(solver, parameters, response)
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        LOGGER.debug(f'Connecting to url {Urls.signing_service} with data: {parameters} and headers:{headers}')
        return session.post(Urls.signing_service, data=parameters, headers=headers)


class AssumedRoleAuthenticator(LoggerMixin):
    """Interfaces with aws authentication mechanisms, providing pre signed urls, or authenticated sessions."""

    def __init__(self, arn, session_duration=3600, region=None):
        self.arn = arn
        self.session_duration = session_duration
        self._sts_connection: StsClient = boto3.client('sts', region_name=region)
        self.region = region or self._get_region()
        self._assumed_role = self._get_assumed_role(arn)
        self.urls = Urls(self.region)

    def _get_region(self):
        region = self._sts_connection._client_config.region_name  # pylint: disable=protected-access
        return region if region != 'aws-global' else DEFAULT_REGION

    def _get_assumed_role(self, arn):
        self.logger.debug('Trying to assume role "%s".', arn)
        try:
            return self._sts_connection.assume_role(RoleArn=arn,
                                                    RoleSessionName="AssumeRoleSession",
                                                    DurationSeconds=self.session_duration)
        except botocore.exceptions.ParamValidationError as error:
            raise InvalidArn(f'The arn you provided is incorrect: {error}') from None
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
        return {key: credentials.get(value) for key, value in payload.items()}

    def _get_signin_token(self):  # we can pass a duration here.
        self.logger.debug('Trying to get signin token.')
        params = {'Action': 'getSigninToken',
                  'Session': json.dumps(self.session_credentials)}
        response = requests.get(self.urls.federation, params=params, timeout=5)
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

    def get_sso_authenticated_session(self):
        """Authenticates to Single Sign On and returns an authenticated session.

        Returns:
            session (AwsSession): An authenticated session with headers and cookies set.

        """
        return self._authenticate_with_default_settings(self.urls.regional_single_sign_on_home)

    def get_cloudformation_authenticated_session(self):
        """Authenticates to cloudformation and returns an authenticated session.

        Returns:
            session (AwsSession): An authenticated session with headers and cookies set.

        """
        session = self._authenticate_with_default_settings(self.urls.regional_cloudformation_home)
        # Authorization: AWS4-HMAC-SHA256 Credential=ASIAR5SEAWIDACLHP224/20230825/eu-west-1/cloudformation/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-user-agent, Signature=33e81e4480e3b438474da1b37d6c670f77b2be7b394299771fe89afbc2a2c48a
        # X-Amz-Content-Sha256 3fb563d96748e13e09dec79da43734f745777cc7b4ae922cfd622475d2ecfa32
        # X-Amz-Date 20230825T142026Z
        # x-amz-security-token IQoJb3JpZ2luX2VjEH8aCWV1LXdlc3QtMSJHMEUCIA48E23JzQ+V3YIvx0R72U2Tphx+qTe8o0+WYYKw6SQOAiEAtlYEhx9vHEnOCfE/SgB2sOrg9SLGv77QVGnrGyWJCrQq9AIIRxACGgwxMzIyMTI4OTYyNjIiDAag3P+0EXILZu0tDCrRAsZ5xrUEvIkfkwP3x+wtc8orKQGoXZ7bR2f1+oKNkuVLJImRlchDmdCbOqmv1xnlmHDucUBcwZta7gWyaloxwuOVmM4ctrINn6xN2FbVRUWEM80CZgoWfIc/8pvRuTgHvapoKtyCUADBHJjCK0xFYWQh067ah20EVKIbvpyds5fItbG2hPhugl/CDXmNyU3g5Qaq4N/4JgczNZ9Fsqn+Ftn2qVCA8k/3NfsXIvHCLXs/h44bWhwUr9Ta2q0XdTgDZCtDo72p0/SeRc1zKrtvJyVmfkYipzxqPfBdlVXKKy5yM0tyczr4tj586/jPAFjNhRHz+fqOuErIwQpYKHk8QxyQHXMr7Hzslz2YzH+RCl7ibGJikaQfcy4rZG75jCqGx7TzQrAjsYR1FdwrQq+Gg8arGFRKjaSFuyr9q/PhunzltFVxR+poYPAR7GSsqMbyLtEw796ipwY6hwJ3i9PQcxabIDc+5lTqlF+Ok9/zuwe0HJUuW9wYtc/KWeLHB3OB/dYyv1rzJiu1DSxnjQ3Y08wM/aguWmnIi1b0edAzoC8Tf6wQcHBo1Cq8h8Y59xzf892yB/zJVRFtdykqCrvoEzeFDN+G7Dbv4HqEISnIlnRWyDnjOTHKV5VQWUn/S2fL91XmQic3SqUl0BLnRtBNfJlzgLVSgdLdOQfH5B6jrnI+GuhcT+PhQauNaen1/c6OnYnqLIEP3FoaR9c8mDHZMNXjS2b4O3y+NQ2d7UhJLY/Va7K6bv8pdfrgKFP7akxQvBAhNI9Dc+gq9xyEu4Ny/orgETDTHt1yrsy1R+bRWBC1JA==
        # X-Amz-User-Agent aws-sdk-js/2.1347.0 promise

        # session.x_amz_info
        # XAmz(
        #     security_token='IQoJb3JpZ2luX2VjEH4aCWV1LXdlc3QtMSJHMEUCIQCSTy9ZdQRXm7ZaLrpl48w34LTlSr3kWw9+R5L+KBPv9QIgB3qR0ugxcyNOdrGOzMSC2ZqtateBYwB70b1vEJtgSO4qigIIRxABGgw0MDE2MzUzODMwOTEiDG0skzyvyu+r0izBsSrnAZEATpGU3uUFusRXiNfRKM0aU5IUdZvKypPICBtr/rhoJ3f0AM+MrpOteHrb6WuQ2je/0n/c3KL5Bl3tMAp7Qird795lsCkuvZureR/nYTCbAIcXJrrSrCNALrrd2bxeHxTulKMyGnWIt+VvMvTHmuoLU2tAsuPZ0qEvi/ivHODYguj2rI/BY10NsAVMsEIwCkAjSOkenl4xAmphy7gw0kWWPqvhZvULe7v5RDJyV9Le3uYkQx0+WRCv34mzhjBWCWpvNkVrEIiFUm29krHcjDW/qgbAFtafEn/WLh22E++nv2bZm8EjEjCV6aKnBjqPAQXOk0kZXQxEFyYshtfuPRShRspIsOnVuniTLhkLmOFXXKv4HXosmk369E0PITVAWshOAQ0adb+ZuPJ2vNjjqn60sTmRtIVKT6oyz1QghaJltHRfz7CDrqjIz+Xr2afO0w1w1VS+NlljGavEwJbORWTFNquGEpTgEU0x0YyPcfDNNOoQ/JJLW81fK3fN5qNE',
        #     date='20230825T141823Z',
        #     algorithm='AWS4-HMAC-SHA256',
        #     credential='ASIAV3A2VS4Z2I3N2GRA/20230825/eu-west-1/signin/aws4_request',
        #     signed_headers='host',
        #     signature='d9c678be2bd6e5d11b8395ef83b5c16588596577a37ad7ad21987edda4c40b4e')
        session.headers.update(())

    def _get_cloudformation_authenticated_console_credentials(self, session):
        response = session.post(self.urls.regional_cloudformation_credentials)
        if not response.ok:
            LOGGER.error(f'Received unexpected response: {response.text} with status code {response.status_code}')
            raise UnexpectedResponse('Unable to get a valid authenticated session for cloudformation console.')
        return response.json()

    def get_billing_authenticated_session(self):
        """Authenticates to billing and returns an authenticated session.

        Returns:
            session (AwsSession): An authenticated session with headers and cookies set.

        """
        url = self.urls.global_billing_home
        params = {'state': 'hashArgs#', 'skipRegion': 'true', 'region': 'us-east-1'}
        csrf_token_data = CsrfTokenData(entity_type='input',
                                        attributes={'id': 'xsrfToken'},
                                        attribute_value='value',
                                        headers_name='x-awsbc-xsrf-token')
        return self._authenticate(url, params, csrf_token_data)

    def _authenticate_with_default_settings(self, url):
        params = {'hashArgs': '#', 'region': self.region}
        csrf_token_data = CsrfTokenData(entity_type='meta',
                                        attributes={'name': 'tb-data'},
                                        attribute_value='content',
                                        headers_name='x-csrf-token')
        transform = lambda x: json.loads(x).get('csrfToken')  # noqa
        return self._authenticate(url, params, csrf_token_data, transform)

    def _authenticate(self, url, params, token_data, transform=lambda x: x):
        session = AwsSession()
        session.get(self.get_signed_url())
        dashboard = session.get(url, params=params)
        session.x_amz_info = RootAuthenticator.get_x_amz_info(dashboard.history[-3].headers.get('Location'))
        return session.get_console_session(dashboard, token_data, token_transform=transform)
