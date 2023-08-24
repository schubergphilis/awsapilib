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
from dataclasses import dataclass
from random import choice

from fake_useragent import UserAgent

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
