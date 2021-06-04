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
import urllib

from dataclasses import dataclass
from requests import Session

from awsapilib.authentication import LoggerMixin, Urls
from awsapilib.captcha import Solver, Iterm
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


class AccountManager(LoggerMixin):

    def __init__(self, solver=Iterm):
        self.session = Session()
        if not issubclass(solver, Solver):
            raise NotSolverInstance
        self._solver = solver()
        self._console_home_url = f'{Urls.console}/console/home'
        self._singin_url = f'{Urls.sign_in}/signin'
        self._reset_url = f'{Urls.sign_in}/resetpassword'

    @staticmethod
    def _get_captcha_info(response):
        properties = response.json().get('properties', {})
        url = properties.get('CaptchaURL')
        captcha_token = properties.get('CES')
        captcha_obfuscation_token = properties.get('captchaObfuscationToken')
        return Captcha(url, captcha_token, captcha_obfuscation_token)

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
        parameters.update({'csrf': self.session.cookies.get('aws-signin-csrf')})
        response = self.session.post(self._singin_url, data=parameters)
        parameters = self._update_parameters_with_captcha(parameters, response)
        final_response = self.session.post(self._singin_url, data=parameters)
        if not all([final_response.ok, final_response.json().get('state', '') == 'SUCCESS']):
            self.logger.error(f'Error resolving account type, response: {final_response.text}')
            return False
        return True

    def request_password_reset(self, email):
        if not self._resolve_account_type(email):
            return False
        parameters = {'action': 'captcha',
                      'forgotpassword': True,
                      'csrf': self.session.cookies.get('aws-signin-csrf')}
        response = self.session.post(self._singin_url, data=parameters)
        parameters = {'action': 'getResetPasswordToken',
                      'email': email,
                      'csrf': self.session.cookies.get('aws-signin-csrf')}
        parameters = self._update_parameters_with_captcha(parameters, response)
        completed_response = self.session.post(self._singin_url, data=parameters)
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
