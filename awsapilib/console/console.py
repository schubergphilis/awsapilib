#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: console.py
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
Main code for console.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import logging
import os
import urllib

from dataclasses import dataclass
from requests import Session

from awsapilib.authentication import LoggerMixin, Urls, Domains
from awsapilib.authentication.authentication import BaseAuthenticator, FilterCookie, CsrfTokenData
from awsapilib.captcha import Solver, Iterm, Terminal
from .consoleexceptions import (NotSolverInstance,
                                InvalidAuthentication,
                                ServerError,
                                UnableToResolveAccount,
                                UnableToUpdateAccount)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''30-06-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''console'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


CONSOLE_SOLVER = Iterm if 'iterm' in os.environ.get('TERM_PROGRAM', '').lower() else Terminal  # pylint: disable=invalid-name


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
    redirect_url: str


class RootAuthenticator(BaseAuthenticator):
    """Interacts with the console to retrieve console and billing page sessions."""

    def __init__(self, session, region):
        super().__init__(region=region)
        self._session = session
        self.region = region
        self.urls = Urls(self.region)
        self.domains = Domains(self.region)

    def _get_console_root_session(self, redirect_url):
        service = 'console'
        home_url_response = self._get_response(redirect_url, extra_cookies=[FilterCookie('JSESSIONID', ),
                                                                            FilterCookie('aws-userInfo-signed', ),
                                                                            FilterCookie('aws-creds', ),
                                                                            FilterCookie('aws-creds-code-verifier', )])
        url = home_url_response.headers.get('Location')
        _ = self._get_response(url, extra_cookies=[FilterCookie('aws-userInfo-signed', ),
                                                   FilterCookie('aws-creds', f'{service}'),
                                                   FilterCookie('aws-creds-code-verifier',
                                                                f'{service}')])
        url = f'{self.urls.regional_console_home}'
        params = {'region': self.region}
        _ = self._get_response(url,
                               params=params,
                               extra_cookies=[FilterCookie('JSESSIONID', ),
                                              FilterCookie('aws-userInfo-signed', ),
                                              FilterCookie('aws-creds', f'{service}'),
                                              FilterCookie('aws-creds-code-verifier',
                                                           f'{service}')])
        params.update({'hashArgs': '#'})
        hash_args = self._get_response(url,
                                       params=params,
                                       extra_cookies=[FilterCookie('JSESSIONID', ),
                                                      FilterCookie('aws-userInfo-signed', ),
                                                      FilterCookie('aws-creds', f'{service}'),
                                                      FilterCookie('aws-creds-code-verifier', f'{service}')])
        oauth_url = hash_args.headers.get('Location')
        oauth = self._get_response(oauth_url,
                                   extra_cookies=[FilterCookie('aws-creds', self.domains.sign_in),
                                                  FilterCookie('aws-userInfo-signed', )])
        oauth_challenge = self._get_response(oauth.headers.get('Location'),
                                             extra_cookies=[FilterCookie('JSESSIONID', self.urls.regional_console),
                                                            FilterCookie('aws-userInfo-signed', ),
                                                            FilterCookie('aws-creds-code-verifier', f'/{service}')])
        dashboard = self._get_response(oauth_challenge.headers.get('Location'),
                                       extra_cookies=[FilterCookie('aws-creds', f'/{service}'),
                                                      FilterCookie('JSESSIONID', )])
        if not dashboard.ok:
            self.logger.error(f'Received broken response: {dashboard.text}')
        return dashboard.ok

    def get_billing_root_session(self, redirect_url, unfiltered_session=False):
        """Retreives a billing session, filtered with specific cookies or not depending on the usage.

        Args:
            redirect_url (str): The redirect url provided to initiate the authentication flow after the captcha.
            unfiltered_session (bool): Returns a full session if unfiltered, or a filtered session
                with xsrf token if set to True. Defaults to False.

        Returns:
            session (Session): A valid session.

        """
        if not self._get_console_root_session(redirect_url):
            raise InvalidAuthentication('Unable to get a valid authenticated session for root console.')
        service = 'billing'
        url = f'{self.urls.billing_home}?#/account'
        _ = self._session.get(url)
        url = f'{self.urls.billing_home}'
        hash_args = self._get_response(url,
                                       params={'state': 'hashArgs#'},
                                       extra_cookies=[FilterCookie('JSESSIONID', ),
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
                                                      FilterCookie('JSESSIONID')])
        if unfiltered_session:
            return self._session
        csrf_token_data = CsrfTokenData(entity_type='input',
                                        attributes={'id': 'xsrfToken'},
                                        attribute_value='value',
                                        headers_name='x-awsbc-xsrf-token')
        extra_cookies = [FilterCookie('aws-creds', f'/{service}'),
                         FilterCookie('aws-signin-csrf', '/signin'),
                         FilterCookie('JSESSIONID', )]
        return self._get_session_from_console(dashboard, csrf_token_data, extra_cookies)


class AccountManager(LoggerMixin):
    """Manages accounts password filecycles and can provide a root console session."""

    def __init__(self, solver=CONSOLE_SOLVER):
        self.session = Session()
        if not issubclass(solver, Solver):
            raise NotSolverInstance
        self._solver = solver()
        self._console_home_url = f'{Urls.console_home}'
        self._signin_url = f'{Urls.sign_in}/signin'
        self._reset_url = f'{Urls.sign_in}/resetpassword'
        self._update_url = f'{Urls.sign_in}/updateaccount'

    @staticmethod
    def _get_captcha_info(response):
        try:
            properties = response.json().get('properties', {})
            url = properties.get('CaptchaURL')
            captcha_token = properties.get('CES')
            captcha_obfuscation_token = properties.get('captchaObfuscationToken')
            return Captcha(url, captcha_token, captcha_obfuscation_token)
        except ValueError:
            raise InvalidAuthentication(response.text)

    @staticmethod
    def _get_oidc_info(referer):
        parsed_query = dict(urllib.parse.parse_qsl(referer))
        return Oidc(parsed_query.get('client_id') or
                    parsed_query.get('https://signin.aws.amazon.com/oauth?client_id'),
                    parsed_query.get('code_challenge'),
                    parsed_query.get('code_challenge_method'),
                    parsed_query.get('redirect_uri'))

    def _update_parameters_with_captcha(self, parameters, response):
        captcha = self._get_captcha_info(response)
        parameters.update({'captcha_guess': self._solver.solve(captcha.url),
                           'captcha_token': captcha.token,
                           'captchaObfuscationToken': captcha.obfuscation_token})
        return parameters

    def _resolve_account_type(self, email):
        response = self._resolve_account_type_response(email, {'hashArgs': '#a'})
        if not all([response.ok, response.json().get('state', '') == 'SUCCESS']):
            self.logger.error(f'Error resolving account type, response: {response.text}')
            return False
        return True

    def _resolve_account_type_response(self, email, extra_parameters=None, session=None):
        session_ = session if session else self.session
        parameters = {'action': 'resolveAccountType',
                      'email': email}
        if extra_parameters:
            parameters.update(extra_parameters)
        _ = session_.get(self._console_home_url, params=parameters)
        parameters.update({'csrf': session_.cookies.get('aws-signin-csrf', path='/signin')})
        response = session_.post(self._signin_url, data=parameters)
        parameters = self._update_parameters_with_captcha(parameters, response)
        return session_.post(self._signin_url, data=parameters)

    def request_password_reset(self, email):
        """Requests a password reset for an account by it's email.

        Args:
            email: The email of the account to request the password reset.

        Returns:
            True on success, False otherwise.

        """
        if not self._resolve_account_type(email):
            self.logger.error(f'Could not resolve account type for email: {email}')
            return False
        parameters = {'action': 'captcha',
                      'forgotpassword': True,
                      'csrf': self.session.cookies.get('aws-signin-csrf', path='/signin')}
        response = self.session.post(self._signin_url, data=parameters)
        parameters = {'action': 'getResetPasswordToken',
                      'email': email,
                      'csrf': self.session.cookies.get('aws-signin-csrf', path='/signin')}
        parameters = self._update_parameters_with_captcha(parameters, response)
        completed_response = self.session.post(self._signin_url, data=parameters)
        if not completed_response.ok:
            self.logger.error(f'Error requesting password reset, response: {completed_response.text}')
            return False
        return completed_response.json().get('state', '') == 'SUCCESS'

    def reset_password(self, reset_url, password):
        """Resets password of an aws account.

        Args:
            reset_url: The reset url provided by aws thought the reset password workflow.
            password: The new password to set to the account.

        Returns:
            True on success, False otherwise.

        """
        parsed_url = dict(urllib.parse.parse_qsl(reset_url))
        _ = self.session.get(reset_url)
        parameters = {'action': 'resetPasswordSubmitForm',
                      'confirmpassword': password,
                      'key': parsed_url.get('key'),
                      'newpassword': password,
                      'token': parsed_url.get('token'),
                      'type': 'RootUser',
                      'csrf': self.session.cookies.get('aws-signin-csrf', path='/resetpassword')}
        response = self.session.post(self._reset_url, data=parameters)
        if any([not response.ok,
                not response.json().get('state', '') == 'SUCCESS']):
            self.logger.error(f'Error resetting password, response: {response.text}')
        return response.json().get('state', '') == 'SUCCESS'

    def _get_root_console_redirect(self, email, password, session):
        url = f'{Urls.console_home}'
        parameters = {'hashArgs': '#a'}
        self.logger.debug(f'Trying to get url: {url} with parameters :{parameters}')
        response = session.get(url, params=parameters)
        if not response.ok:
            raise ServerError(f'Unsuccessful response received: {response.text} '
                              f'with status code: {response.status_code}')
        oidc = self._get_oidc_info(response.history[0].headers.get('Location'))
        response = self._resolve_account_type_response(email, session=session)
        if any([not response.ok,
                response.json().get('properties', {}).get('captchaStatusToken') is None]):
            raise UnableToResolveAccount(f'Unable to resolve the account, response received: {response.text} '
                                         f'with status code: {response.status_code}')
        parameters = {'action': 'authenticateRoot',
                      'captcha_status_token': response.json().get('properties', {}).get('captchaStatusToken'),
                      'client_id': oidc.client_id,
                      'code_challenge_method': oidc.code_challenge_method,
                      'code_challenge': oidc.code_challenge,
                      'email': email,
                      'mfaSerial': 'undefined',
                      'password': password,
                      'redirect_uri': oidc.redirect_url,
                      'csrf': session.cookies.get('aws-signin-csrf', path='/signin')}
        root_response = session.post(self._signin_url, data=parameters)
        if any([not root_response.ok,
                root_response.json().get('state') == 'FAIL',
                root_response.json().get('properties').get('RedirectTo') is None]):
            raise InvalidAuthentication(f'Unable to authenticate, response received was: {root_response.text} '
                                        f'with status code: {root_response.status_code}')
        return root_response.json().get('properties').get('RedirectTo')

    def _get_billing_session(self, email, password, region, unfiltered_session):
        session = Session()
        authenticator = RootAuthenticator(session, region=region)
        redirect_url = self._get_root_console_redirect(email, password, session)
        return authenticator.get_billing_root_session(redirect_url, unfiltered_session=unfiltered_session)

    def terminate_account(self, email, password, region):
        """Terminates the account of the corresponding info provided.

        Args:
            email: The email of the account to terminate.
            password: The password of the account to terminate.
            region: The region of the console.

        Returns:
            True on success, False otherwise.

        """
        termination_url = f'{Urls.console}/billing/rest/v1.0/account'
        session = self._get_billing_session(email, password, region, unfiltered_session=False)
        response = session.put(termination_url)
        if not response.ok:
            self.logger.error(f'Unsuccessful response received: {response.text} '
                              f'with status code: {response.status_code}')
        return response.ok

    def update_account_name(self, new_account_name, email, password, region):
        """Updates the email of an account to the new one provided.

        Args:
            new_account_name: The new account email.
            email: The current email for authentication.
            password: The password. of the account.
            region: The region of the console.

        Returns:
            True on success.

        Raises:
            UnableToUpdateAccount: On Failure with the corresponding message from the backend service.

        """
        payload = {'action': 'updateAccountName',
                   'newAccountName': new_account_name}
        return self._update_account(email, password, region, payload)

    def update_account_email(self, new_account_email, email, password, region):
        """Updates the name of an account to the new one provided.

        Args:
            new_account_email: The new account name.
            email: The email for authentication.
            password: The password. of the account.
            region: The region of the console.

        Returns:
            True on success.

        Raises:
            UnableToUpdateAccount: On Failure with the corresponding message from the backend service.

        """
        payload = {'action': 'updateAccountEmail',
                   'newEmailAddress': new_account_email,
                   'password': password}
        return self._update_account(email, password, region, payload)

    def _update_account(self, email, password, region, payload):
        update_url = f'{self._update_url}?redirect_uri={Urls.billing_home}#/account'
        session = self._get_billing_session(email, password, region, unfiltered_session=True)
        response = session.get(update_url)
        if not response.ok:
            self.logger.error(f'Unsuccessful response received: {response.text} '
                              f'with status code: {response.status_code}')
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        payload_ = {'redirect_uri': f'{Urls.billing_home}#/account',
                    'csrf': response.cookies.get('aws-signin-csrf', path='/updateaccount')}
        payload_.update(payload)
        response = session.post(self._update_url, headers=headers, data=payload_)
        if any([not response.ok,
                response.json().get('state') == 'FAIL']):
            raise UnableToUpdateAccount(f'Unable to update account info, response received was: {response.text} '
                                        f'with status code: {response.status_code}')
        return True
