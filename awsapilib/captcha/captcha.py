#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: captcha.py
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
Main code for captcha.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import base64
import logging
import os
from abc import ABC, abstractmethod

import requests
from twocaptcha import TwoCaptcha, ValidationException, TimeoutException
from twocaptcha.api import ApiException, NetworkException

from awsapilib.authentication import LoggerMixin
from .captchaexceptions import CaptchaError, UnsupportedTerminal, InvalidOrNoBalanceApiToken

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
LOGGER_BASENAME = '''captcha'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class Solver(ABC, LoggerMixin):
    """Interface for a Solver object."""

    def __call__(self, *args, **kwargs):
        return self

    @abstractmethod
    def solve(self, url):
        """Solves a url."""


class Iterm(Solver):
    """Interactive captcha solver for iTerm terminals."""

    def __init__(self):
        terminal = os.environ.get('TERM_PROGRAM', 'UNKNOWN')
        if 'iterm' not in terminal.lower():
            raise UnsupportedTerminal(terminal)

    def solve(self, url):
        """Presents a captcha image and returns the user's guess for the captcha.

        Args:
            url (str): The url to provide that should have the captcha image.

        Returns:
            guess (str): The guess of the user for the captcha.

        """
        response = requests.get(url)
        if not response.ok:
            raise CaptchaError(response.text)
        image = base64.b64encode(response.content).decode()
        print(f'\033]1337;File=inline=1;width=400px;height=140px:{image}\a\n')
        try:
            guess = input('Captcha: ')
        except KeyboardInterrupt:
            raise CaptchaError(f'User interrupted.\nIf the captcha was not showing correctly please check that the url'
                               f'{url} indeed points to a valid captcha image..') from None
        return guess


class Terminal(Solver):
    """Interactive captcha solver for standard terminals."""

    def solve(self, url):
        """Presents a captcha image url and returns the user's guess for the captcha.

        Args:
            url (str): The url to provide that should have the captcha image.

        Returns:
            guess (str): The guess of the user for the captcha.

        """
        print(f'Please follow {url} and provide the solution.')
        try:
            guess = input('Captcha: ')
        except KeyboardInterrupt:
            raise CaptchaError('User interrupted.') from None
        return guess


class Captcha2(Solver):
    """2captcha solver."""

    def __init__(self, api_token):
        self.solver = self._get_client(api_token)

    @staticmethod
    def _get_client(api_token):
        solver = TwoCaptcha(api_token)
        try:
            balance = solver.balance()
            if not balance:
                raise InvalidOrNoBalanceApiToken('No balance left on the token.')
        except ApiException as msg:
            raise InvalidOrNoBalanceApiToken(msg) from None
        return solver

    def solve(self, url):
        """Presents a captcha image url and returns the captcha.

        Args:
            url (str): The url to provide that should have the captcha image.

        Returns:
            guess (str): The captcha.

        """
        captcha_parameters = {'numeric': 4,
                              'minLength': 6,
                              'maxLength': 6,
                              'phrase': 0,
                              'caseSensitive': 1,
                              'calc': 0,
                              'lang': 'en'}
        try:
            self.logger.debug(f'Trying to get captcha image from url : {url}')
            response = requests.get(url)
            image = base64.b64encode(response.content).decode("utf-8")
            self.logger.debug('Waiting for the solved captcha from 2captcha service.')
            result = self.solver.normal(image, **captcha_parameters)
            self.logger.debug(f'Result for captcha was : {result}')
        except (ValidationException, NetworkException, ApiException, TimeoutException) as msg:
            raise CaptchaError(msg) from None
        return result.get('code')
