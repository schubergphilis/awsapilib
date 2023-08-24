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
   https://google.github.io/styleguide/pyguide.html

"""

import logging
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl

from opnieuw import retry
from pyotp import TOTP

from awsapilib.authentication import RootAuthenticator, AwsSession, CONSOLE_SOLVER
from awsapilib.authentication.authenticationexceptions import (InvalidCaptcha,
                                                               UnableToResolveAccount,
                                                               UnexpectedResponse,
                                                               NotSolverInstance)
from awsapilib.awsapilib import RANDOM_USER_AGENT, LoggerMixin, Urls
from awsapilib.captcha import Solver
from .consoleexceptions import (UnableToCreateVirtualMFA,
                                UnableToEnableVirtualMFA,
                                UnableToDisableVirtualMFA,
                                UnableToGetVirtualMFA,
                                UnableToUpdateAccount,
                                VirtualMFADeviceExists,
                                UnableToResetPassword,
                                UnableToRequestResetPassword)

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
LOGGER_BASENAME = __name__
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


@dataclass
class MFA:
    """Models the MFA device."""

    _data: dict

    @property
    def _url(self):
        return list(self._data)[0]

    @property
    def enabled_date(self):
        """Timestamp of enabled day."""
        return self._data.get(self._url).get('enabledDate', {}).get('time')

    @property
    def id(self):  # pylint: disable=invalid-name
        """Id."""
        return self._data.get(self._url).get('id')

    @property
    def serial_number(self):
        """The serial number of the device."""
        return self._data.get(self._url).get('serialNumber')

    @property
    def user_name(self):
        """The username set on the device."""
        return self._data.get(self._url).get('userName')


@dataclass
class VirtualMFADevice:
    """Models the active MFA device."""

    seed: str
    serial: str


class IamAccess(LoggerMixin):
    """Models the iam access settings and implements the interaction with them."""

    def __init__(self, billing_session):
        self._session = billing_session
        self._api_url = f'{Urls.billing_rest}/v1.0/account/iamaccess'

    def _get_current_state(self):
        response = self._session.get(self._api_url)
        if not response.ok:
            raise UnexpectedResponse(f'Unsuccessful response received: {response.text} '
                                     f'with status code: {response.status_code}')
        return response.json()

    @property
    def billing_console_access(self):
        """Billing console access setting."""
        current_state = self._get_current_state()
        return current_state.get('billingConsoleAccessEnabled')

    @billing_console_access.setter
    def billing_console_access(self, value):
        """Billing console access setting."""
        self._update_setting(value, 'billingConsoleAccessEnabled')

    def _update_setting(self, value, key):
        current_state = self._get_current_state()
        current_state[key] = bool(value)
        response = self._session.put(self._api_url, data=current_state)
        if not response.ok:
            raise UnexpectedResponse(f'Unsuccessful response received: {response.text} '
                                     f'with status code: {response.status_code}')


class MfaManager(LoggerMixin):
    """Models interaction with the api for mfa management."""

    def __init__(self, iam_session):
        self.session = iam_session
        self._api_url = f'{Urls.iam_api}/mfa'

    def _create_virtual_mfa(self, name):
        create_mfa_url = f'{self._api_url}/createVirtualMfa'
        create_payload = {'virtualMFADeviceName': name, 'path': '/'}
        self.logger.debug('Trying to create a virtual mfa')
        response = self.session.post(create_mfa_url, json=create_payload)
        if not response.ok:
            if response.status_code == 409:
                raise VirtualMFADeviceExists(response.text)
            raise UnableToCreateVirtualMFA(response.text)
        serial_number = response.json().get('serialNumber')
        seed = response.json().get('base32StringSeed')
        self.logger.debug(f'Successfully created virtual mfa with serial number: "{serial_number}"')
        return serial_number, seed

    def _enable_virtual_mfa(self, serial_number, seed):
        enable_mfa_url = f'{self._api_url}/enableMfaDevice'
        totp = TOTP(seed)
        self.logger.debug('Calculating the first totp.')
        authentication_code_1 = totp.now()
        self.logger.debug('Waiting 30 seconds for the next totp.')
        time.sleep(30)
        authentication_code_2 = totp.now()
        enable_payload = {'authenticationCode1': authentication_code_1,
                          'authenticationCode2': authentication_code_2,
                          'serialNumber': serial_number,
                          'userName': ''}
        self.logger.debug('Trying to enable the virtual mfa.')
        response = self.session.post(enable_mfa_url, json=enable_payload)
        if not response.ok:
            raise UnableToEnableVirtualMFA(response.text)
        self.logger.info(f'Successfully enabled mfa device with serial number "{serial_number}"')
        return VirtualMFADevice(seed, serial_number)

    def create_virtual_device(self, name='root-account-mfa-device'):
        """Creates a virtual MFA device with the provided name.

        Args:
            name: The name of the virtual MFA device, defaults to "root-account-mfa-device"

        Returns:
            seed (str): The secret seed of the virtual MFA device. This needs to be saved in a safe place!!

        Raises:
            VirtualMFADeviceExists, UnableToCreateVirtualMFA, UnableToEnableVirtualMFA on respective failures.

        """
        serial_number, seed = self._create_virtual_mfa(name)
        return self._enable_virtual_mfa(serial_number, seed)

    def delete_virtual_device(self, serial_number):
        """Deletes a virtual MFA with the provided serial number.

        Args:
            serial_number: The serial number of the virtual MFA device to delete.

        Returns:
            True on success

        Raises:
            UnableToDisableVirtualMFA on failure.

        """
        deactivate_mfa_url = f'{self._api_url}/deactivateMfaDevice'
        deactivate_payload = {'userName': '', 'serialNumber': serial_number}
        response = self.session.post(deactivate_mfa_url, json=deactivate_payload)
        if not response.ok:
            raise UnableToDisableVirtualMFA(response.text)
        self.logger.info(f'Successfully deleted mfa device with serial number "{serial_number}"')
        return True

    def get_virtual_device(self):
        """Retrieves the virtual MFA device if set.

        Returns:
            mfa_device (MFA): The set virtual MFA device if any else, None.

        """
        response = self.session.get(self._api_url)
        if not response.ok:
            raise UnableToGetVirtualMFA(response.text)
        self.logger.debug(response.json())
        return MFA(response.json().get('_embedded')) if response.json().get('_embedded') else None


class PasswordManager(LoggerMixin):
    """Models interaction for account password reset."""

    def __init__(self, solver=CONSOLE_SOLVER, user_agent=RANDOM_USER_AGENT):
        self._solver = solver()
        if not isinstance(self._solver, Solver):
            raise NotSolverInstance
        self._user_agent = user_agent

    @retry(retry_on_exceptions=InvalidCaptcha, max_calls_total=5, retry_window_after_first_call_in_seconds=120)
    def request_password_reset(self, email):
        """Requests a password reset for an account by its email.

        Args:
            email: The email of the account to request the password reset.

        Returns:
            True on success, False otherwise.

        Raises:
            UnableToRequestResetPassword if unsuccessful

        """
        self.logger.debug(f'Trying to resolve account type for email :{email}')
        session = AwsSession()
        authenticator = RootAuthenticator(self._solver, self._user_agent)
        try:
            secrets = authenticator.parse_home_page_redirects(session)
            authenticator.resolve_account_type(session, authenticator.metadata_manager, email, *secrets, self._solver)
        except UnableToResolveAccount:
            raise UnableToRequestResetPassword(f'Could not resolve account type for email: {email}') from None
        parameters = {'action': 'captcha',
                      'forgotpassword': True,
                      'csrf': session.cookies.get('aws-signin-csrf', path='/signin')}
        self.logger.debug('Starting the forgot password workflow.')
        response = session.post(Urls.signing_service, data=parameters)
        parameters = {'action': 'getResetPasswordToken',
                      'email': email,
                      'csrf': session.cookies.get('aws-signin-csrf', path='/signin')}
        self.logger.debug('Getting password reset captcha.')
        parameters = authenticator.update_parameters_with_captcha(self._solver, parameters, response)
        self.logger.debug('Requesting to reset the password.')
        response = session.post(Urls.signing_service, data=parameters)
        if not authenticator.validate_response(response):
            raise UnableToRequestResetPassword(response.text)
        self.logger.debug(f'Request responded to with text: {response.text} and status code {response.status_code}')
        self.logger.info('Requested password reset successfully')
        return True

    @retry(retry_on_exceptions=InvalidCaptcha, max_calls_total=5, retry_window_after_first_call_in_seconds=120)
    def reset_password(self, reset_url, password):
        """Resets password of an aws account.

        Args:
            reset_url: The reset url provided by aws thought the reset password workflow.
            password: The new password to set to the account.

        Returns:
            True on success, False otherwise.

        Raises:
            UnableToResetPassword on failure

        """
        session = AwsSession()
        parsed_url = dict(parse_qsl(reset_url))
        session.get(reset_url)
        parameters = {'action': 'resetPasswordSubmitForm',
                      'confirmpassword': password,
                      'key': parsed_url.get('key'),
                      'newpassword': password,
                      'token': parsed_url.get('token'),
                      'type': 'RootUser',
                      'csrf': session.cookies.get('aws-signin-csrf', path='/resetpassword')}
        response = session.post(Urls.password_reset, data=parameters)
        success = RootAuthenticator.validate_response(response)
        if not success:
            raise UnableToResetPassword(response.text)
        self.logger.debug(f'Request responded with text: {response.text} and status code {response.status_code}')
        self.logger.info('Password reset successful')
        return True


class AccountManager(LoggerMixin):
    """Models basic communication with the server for account and password management."""

    # pylint: disable=too-many-arguments
    def __init__(self, email, password, region, mfa_serial=None, solver=CONSOLE_SOLVER, user_agent=RANDOM_USER_AGENT):
        self.email = email
        self.password = password
        self.region = region
        self._mfa_serial = mfa_serial
        self._solver = solver
        self._user_agent = user_agent
        self._iam = None
        self._mfa = None
        self._account_id = None

    def terminate_account(self):
        """Terminates the account matching the info provided.

        Returns:
            True on success, False otherwise.

        """
        authenticator = RootAuthenticator(self._solver, self._user_agent)
        session = authenticator.get_billing_root_session(self.email,
                                                         self.password,
                                                         mfa_serial=self._mfa_serial)
        response = session.put(Urls.account_management)
        if not response.ok:
            self.logger.error(f'Unsuccessful response received: {response.text} '
                              f'with status code: {response.status_code}')
        return response.ok

    def update_account_name(self, new_account_name):
        """Updates the email of an account to the new one provided.

        Args:
            new_account_name: The new account email.

        Returns:
            True on success.

        Raises:
            UnexpectedResponse, UnableToUpdateAccount:
                On Failure with the corresponding message from the backend service.

        """
        payload = {'action': 'updateAccountName',
                   'newAccountName': new_account_name}
        return self._update_account(payload)

    def update_account_email(self, new_account_email):
        """Updates the name of an account to the new one provided.

        Args:
            new_account_email: The new account name.

        Returns:
            True on success.

        Raises:
            UnexpectedResponse, UnableToUpdateAccount:
                On Failure with the corresponding message from the backend service.

        """
        payload = {'action': 'updateAccountEmail',
                   'newEmailAddress': new_account_email,
                   'password': self.password}
        success = self._update_account(payload)
        if success:
            self.email = new_account_email
        return success

    def _update_account(self, payload):
        authenticator = RootAuthenticator(self._solver, self._user_agent)
        session = authenticator.get_billing_root_session(self.email,
                                                         self.password,
                                                         mfa_serial=self._mfa_serial)
        params = {'redirect_uri': Urls.billing_home_account}
        response = session.get(Urls.account_update, params=params)
        if not response.ok:
            raise UnexpectedResponse(f'Unsuccessful response received: {response.text} '
                                     f'with status code: {response.status_code}')
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        params.update(**{'csrf': response.cookies.get('aws-signin-csrf', path='/updateaccount')},
                      **payload)
        response = session.post(Urls.account_update, headers=headers, data=params)
        success = authenticator.validate_response(response)
        if not success:
            raise UnableToUpdateAccount(response.text)
        self.logger.info('Account information updated successfully')
        return True

    @property
    def mfa(self):
        """Retrieves an MFA manager.

        Returns:
            mfa_manager (MfaManager): The mfa manager object

        """
        if self._mfa is None:
            authenticator = RootAuthenticator(self._solver, self._user_agent)
            session = authenticator.get_iam_root_session(self.email,
                                                         self.password,
                                                         mfa_serial=self._mfa_serial)
            self._mfa = MfaManager(session)
        return self._mfa

    @property
    def iam(self):
        """IAM."""
        if self._iam is None:
            authenticator = RootAuthenticator(self._solver, self._user_agent)
            session = authenticator.get_billing_root_session(self.email,
                                                             self.password,
                                                             mfa_serial=self._mfa_serial)
            self._iam = IamAccess(session)
        return self._iam

    @property
    def account_id(self):
        """IAM."""
        if self._account_id is None:
            authenticator = RootAuthenticator(self._solver, self._user_agent)
            session = authenticator.get_billing_root_session(self.email,
                                                             self.password,
                                                             mfa_serial=self._mfa_serial)
            response = session.get(Urls.account_management)
            if not response.ok:
                self.logger.error(f'Unsuccessful response received: {response.text} '
                                  f'with status code: {response.status_code}')
            self._account_id = response.json().get('accountId')
        return self._account_id
