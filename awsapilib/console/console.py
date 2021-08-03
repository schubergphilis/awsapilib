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

from awsapilib.authentication import LoggerMixin, Urls
from awsapilib.captcha import Solver, Iterm, Terminal
from .consoleexceptions import NotSolverInstance

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


@dataclass
class Captcha:
    url: str
    token: str
    obfuscation_token: str


@dataclass
class Oidc:
    client_id: str
    code_challenge: str
    code_challenge_method: str
    redirect_url: str


console_solver = Iterm if os.environ.get('TERM_PROGRAM', '').lower() == 'iterm' else Terminal


class AccountManager(LoggerMixin):

    def __init__(self, solver=console_solver):
        self.session = Session()
        if not issubclass(solver, Solver):
            raise NotSolverInstance
        self._solver = solver()
        self._console_home_url = f'{Urls.console}/console/home'
        self._signin_url = f'{Urls.sign_in}/signin'
        self._reset_url = f'{Urls.sign_in}/resetpassword'

    @staticmethod
    def _get_captcha_info(response):
        properties = response.json().get('properties', {})
        url = properties.get('CaptchaURL')
        captcha_token = properties.get('CES')
        captcha_obfuscation_token = properties.get('captchaObfuscationToken')
        return Captcha(url, captcha_token, captcha_obfuscation_token)

    @staticmethod
    def _get_oidc_info(referer):
        parsed = urllib.parse.parse_qs(referer)
        return Oidc(parsed.get('https://signin.aws.amazon.com/oauth?client_id').pop(),
                    parsed.get('code_challenge').pop(),
                    parsed.get('code_challenge_method').pop(),
                    parsed.get('redirect_uri').pop())

    def _update_parameters_with_captcha(self, parameters, response):
        captcha = self._get_captcha_info(response)
        parameters.update({'captcha_guess': self._solver.solve(captcha.url),
                           'captcha_token': captcha.token,
                           'captchaObfuscationToken': captcha.obfuscation_token})
        return parameters

    def _resolve_account_type(self, email):
        parameters = {'hashArgs': '#a',
                      'action': 'resolveAccountType',
                      'email': email}
        _ = self.session.get(self._console_home_url, params=parameters)
        parameters.update({'csrf': self.session.cookies.get('aws-signin-csrf', path='/signin')})
        response = self.session.post(self._signin_url, data=parameters)
        parameters = self._update_parameters_with_captcha(parameters, response)
        final_response = self.session.post(self._signin_url, data=parameters)
        if not all([final_response.ok, final_response.json().get('state', '') == 'SUCCESS']):
            self.logger.error(f'Error resolving account type, response: {final_response.text}')
            return False
        return True

    def _resolve_account_type_response(self, email):
        parameters = {'hashArgs': '#a',
                      'action': 'resolveAccountType',
                      'email': email}
        _ = self.session.get(self._console_home_url, params=parameters)
        parameters.update({'csrf': self.session.cookies.get('aws-signin-csrf', path='/signin')})
        response = self.session.post(self._signin_url, data=parameters)
        parameters = self._update_parameters_with_captcha(parameters, response)
        return self.session.post(self._signin_url, data=parameters)

    def request_password_reset(self, email):
        if not self._resolve_account_type(email):
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
        parsed_url = urllib.parse.parse_qs(reset_url)
        _ = self.session.get(reset_url)
        parameters = {'action': 'resetPasswordSubmitForm',
                      'confirmpassword': password,
                      'key': parsed_url.get('key').pop(),
                      'newpassword': password,
                      'token': parsed_url.get('token').pop(),
                      'type': 'RootUser',
                      'csrf': self.session.cookies.get('aws-signin-csrf', path='/resetpassword')}
        response = self.session.post(self._reset_url, data=parameters)
        if not response.ok:
            self.logger.error(f'Error resetting password, response: {response.text}')
            return False
        return response.json().get('state', '') == 'SUCCESS'

    # def get_root_console(self, email, password):
    #     parameters = {'action': 'authenticateRoot',
    #                   'captcha_status_token': captchaStatusToken,
    #                   'client_id': s.oidcState.clientID,
    #                   'code_challenge_method': s.oidcState.codeChallengeMethod,
    #                   'code_challenge': s.oidcState.codeChallenge,
    #                   'email': email,
    #                   'mfaSerial': 'undefined',
    #                   'password': password,
    #                   'redirect_uri': s.oidcState.redirectURL,
    #                   'csrf': self.session.cookies.get('aws-signin-csrf')
    #                   }
    #     response = self.session.post(self._signin_url, data=parameters)
    #     if not response.ok:
    #         self.logger.error(f'Error resetting password, response: {response.text}')
    #         return False
    #     return response.json().get('state', '') == 'SUCCESS'
