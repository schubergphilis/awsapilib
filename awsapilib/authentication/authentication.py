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
import urllib

import boto3
import botocore
import requests
from boto3_type_annotations.sts import Client as StsClient

from awsapilib.awsapilib import (Urls,
                                 LoggerMixin,
                                 AwsSession,
                                 DEFAULT_REGION,
                                 CsrfTokenData)
from awsapilib.awsapilibexceptions import InvalidCredentials, NoSigninTokenReceived
from .authenticationexceptions import InvalidArn

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
        url = self.urls.regional_single_sign_on_home
        params = {'region': self.region, 'hashArgs': '#'}
        csrf_token_data = CsrfTokenData(entity_type='meta',
                                        attributes={'name': 'tb-data'},
                                        attribute_value='content',
                                        headers_name='x-csrf-token')
        transform = lambda x: json.loads(x).get('csrfToken')  # noqa
        return self._authenticate(url, params, csrf_token_data, transform)

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

    def get_cloudformation_authenticated_session(self):
        """Authenticates to cloudformation and returns an authenticated session.

        Returns:
            session (AwsSession): An authenticated session with headers and cookies set.

        """
        url = self.urls.regional_cloudformation_home
        params = {'hashArgs': '#', 'region': self.region}
        csrf_token_data = CsrfTokenData(entity_type='meta',
                                        attributes={'name': 'tb-data'},
                                        attribute_value='content',
                                        headers_name='x-cfn-xsrf-token')
        transform = lambda x: json.loads(x).get('csrfToken')  # noqa
        return self._authenticate(url, params, csrf_token_data, transform)

    def _authenticate(self, url, params, token_data, transform=lambda x: x):
        session = AwsSession()
        session.get(self.get_signed_url())
        dashboard = session.get(url, params=params)
        return session.get_console_session(dashboard, token_data, token_transform=transform)
