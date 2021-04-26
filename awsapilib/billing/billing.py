#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: billing.py
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
Main code for billing.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import logging
import time
from datetime import datetime, timedelta

from bs4 import BeautifulSoup as Bfs

from awsapilib.authentication import Authenticator, LoggerMixin
from awsapilib.authentication import InvalidCredentials

from .billingexceptions import (InvalidCountryCode,
                                NonEditableSetting,
                                IAMAccessDenied,
                                InvalidCurrency,
                                ServerError)


__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''30-03-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''billing'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class Tax(LoggerMixin):
    """Models the tax settings of the billing console."""

    def __init__(self, billing):
        self._billing = billing
        self._endpoint = f'{self._billing.rest_api}/taxexemption/heritage'
        self._available_country_codes = None

    @property
    def available_country_codes_eu(self):
        """The available country codes of the tax settings for eu.

        Returns:
            codes (list): Available country codes

        """
        if self._available_country_codes is None:
            url = f'{self._billing.rest_api}/taxexemption/eu/vat/countries'
            response = self._billing.session.get(url)
            if response.status_code == 401:
                raise InvalidCredentials
            if not response.ok:
                self.logger.error(f'Failed to retrieve inheritance state, response: {response.text}')
                return None
            self._available_country_codes = response.json().get('supportedCountryCodes', [])
        return self._available_country_codes

    @property
    def inheritance(self):
        """The inheritance settings of the billing preferences.

        Returns:
            setting (bool): True if set, False otherwise.

        """
        response = self._billing.session.get(self._endpoint)
        if response.status_code == 401:
            raise InvalidCredentials
        if not response.ok:
            self.logger.error(f'Failed to retrieve inheritance state, response: {response.text}')
            return None
        return response.json().get('customerHeritageStatus', '') == 'OptIn'

    @inheritance.setter
    def inheritance(self, value: bool):
        """The inheritance settings setter of the billing preferences.

        Returns:
            None

        """
        if self.inheritance == value:
            return
        self._is_editable()
        parameters = {'heritageStatus': 'OptIn' if value else 'OptOut'}
        response = self._billing.session.post(self._endpoint, params=parameters)
        if not response.ok:
            self.logger.error(f'Failed to retrieve inheritance state, response: {response.text}')

    def _is_editable(self):
        parameters = {'heritageStatus': 'OptIn'}
        response = self._billing.session.get(self._endpoint, params=parameters)
        if not response.json().get('heritageStatusEditable'):
            timestamp = response.json().get('effectiveTimestamp')
            unlock_time = (datetime.fromtimestamp(timestamp / 1000) + timedelta(minutes=15))
            wait_time = unlock_time - datetime.now()
            raise NonEditableSetting(f'API is not enabled for {wait_time} more.')
        return True

    #  pylint: disable=too-many-arguments
    def set_information(self, address, city, postal_code, legal_name, vat_number, country_code, state=None):
        """The inheritance settings setter of the billing preferences.

        Returns:
            None

        """
        country_code = country_code.upper()
        if country_code not in self.available_country_codes_eu:
            raise InvalidCountryCode(f'{country_code} provided is not valid. '
                                     f'Valid ones are {self.available_country_codes_eu}')
        payload = {'address': {'addressLine1': address,
                               'addressLine2': None,
                               'city': city,
                               'countryCode': country_code,
                               'postalCode': postal_code,
                               'state': state,
                               },
                   'authority': {'country': country_code,
                                 'state': None},
                   'legalName': legal_name,
                   'localTaxRegistration': False,
                   'registrationId': vat_number,
                   }
        url = f'{self._billing.rest_api}/taxexemption/eu/vat/information'
        response = self._billing.session.put(url, json=payload)
        if not response.ok:
            self.logger.error(f'Failed to set information, response: {response.text}')
        return response.ok


class Preferences(LoggerMixin):
    """Models the preferences of the billing console."""

    def __init__(self, billing):
        self._billing = billing

    @property
    def _preferences_endpoint(self):
        return f'{self._billing.rest_api}/preferences'

    @property
    def _values(self):
        response = self._billing.session.get(self._preferences_endpoint)
        if not response.ok:
            self.logger.error(f'Failed to retrieve inheritance state, response: {response.text}')
            return {}
        return response.json()

    @property
    def pdf_invoice_by_mail(self):
        """The setting of the pdf invoice by email.

        Returns:
            setting (bool): True if set, False otherwise.

        """
        values = self._values
        if not values:
            raise SystemError('Could not retrieve the preferences!')
        return values.get('pdfInvoiceByEmail') == 'Y'

    @pdf_invoice_by_mail.setter
    def pdf_invoice_by_mail(self, value: bool):
        """The setting for the setting of the pdf invoice by email.

        Returns:
            None.

        """
        if self.pdf_invoice_by_mail == value:
            return
        payload = {'pdfInvoiceByEmail': 'Y' if value else 'N'}
        response = self._billing.session.put(self._preferences_endpoint, json=payload)
        if not response.ok:
            self.logger.error(f'Failed to retrieve inheritance state, response: {response.text}')

    @property
    def credit_sharing(self):
        """The setting of the credit sharing.

        Returns:
            setting (bool): True if set, False otherwise.

        """
        endpoint = f'{self._billing.rest_api}/sharingpreferences/getcreditsharing'
        response = self._billing.session.get(endpoint)
        if not response.ok:
            self.logger.error(f'Failed to retrieve credit sharing state, response: {response.text}')
            return {}
        return response.json().get('creditEnabled')

    @credit_sharing.setter
    def credit_sharing(self, value: bool):
        """The setter of the setting of the credit sharing.

        Returns:
            None.

        """
        if self.credit_sharing == value:
            return
        endpoint = f'{self._billing.rest_api}/sharingpreferences/setcreditsharing'
        payload = {'creditEnabled': bool(value)}
        response = self._billing.session.put(endpoint, json=payload)
        if not response.ok:
            self.logger.error(f'Failed to retrieve credit sharing state, response: {response.text}')


class Billing(LoggerMixin):
    """Models Control Tower by wrapping around service catalog."""

    def __init__(self, arn, region=None):
        self.aws_authenticator = Authenticator(arn)
        self.session = self._get_authenticated_session()
        self.region = region or self.aws_authenticator.region
        self.rest_api = 'https://console.aws.amazon.com/billing/rest/v1.0'
        self._sor_info_ = None
        self._payment_instrument_ids = None
        self._marketplace_id = None

    def _get_authenticated_session(self):
        return self.aws_authenticator.get_billing_authenticated_session()

    @property
    def account_id(self):
        """Account id."""
        return self._sor_info.get('accountId')

    @property
    def sor_id(self):
        """Sor id."""
        return self._sor_info.get('sor', {}).get('sorId')

    @property
    def _sor_info(self):
        if self._sor_info_ is None:
            url = f'{self.rest_api}/sellerofrecord/getsorbyaccount'
            response = self.session.get(url)
            if response.status_code == 401:
                raise InvalidCredentials
            if not response.ok:
                self.logger.error(f'Could not retrieve sor info, response: {response.text}')
                self._sor_info_ = []
            self._sor_info_ = response.json()
        return self._sor_info_

    @property
    def tax(self):
        """Tax settings.

        Returns:
            tax (Tax): The tax settings object.

        """
        return Tax(self)

    @property
    def preferences(self):
        """Preferences settings.

        Returns:
            preferences (Preferences): The preferences settings object.

        """
        return Preferences(self)

    @property
    def currency(self):
        """Currency settings.

        Returns:
            currency (str): The currency set.

        """
        url = f'{self.rest_api}/account/fxpaymentinfopapyrus'
        response = self.session.get(url)
        if not response.ok:
            self.logger.error(f'Failed to retrieve currency setting, response: {response.text}')
            return None
        return response.json().get('currencyPreference')

    @currency.setter
    def currency(self, value):
        """Setter for currency settings.

        Returns:
            None

        """
        url = f'{self.rest_api}/account/currencypreference'
        response = self.session.put(url, json=value.upper())
        if not response.ok:
            if response.json().get('type') == 'InvalidParameterException':
                raise InvalidCurrency(value)
            self.logger.error(f'Failed to set currency setting, response: {response.text}')

    def _validate_iam_access(self):
        url = f'{self.rest_api}/account/iamaccess'
        response = self.session.get(url)
        if not response.ok:
            self.logger.error(f'Failed to get iam access settings, response: {response.text}')
            return {}
        if response.json().get('type') == 'AccessDeniedException':
            raise IAMAccessDenied
        return response.json()

    @property
    def iam_access(self):
        """IAM access to billing setting."""
        return self._validate_iam_access().get('billingConsoleAccessEnabled', False)

    @iam_access.setter
    def iam_access(self, value):
        """IAM access to billing setting."""
        data = self._validate_iam_access()
        if data:
            url = f'{self.rest_api}/account/iamaccess'
            data.update({'billingConsoleAccessEnabled': bool(value)})
            response = self.session.put(url, json=data)
            if not response.ok:
                self.logger.error(f'No IAM role access provided to the console, response: {response.text}')

    @property
    def _region_states(self):
        url = f'{self.rest_api}/account/accountregionstates'
        response = self.session.get(url)
        if response.status_code == 401:
            raise InvalidCredentials
        if not response.ok:
            self.logger.error(f'Could not retrieve region states, response: {response.text}')
            return []
        return response.json().get('accountRegionStateList', [])

    @property
    def enabled_region_states(self):
        """Enabled region states."""
        return [region.get('regionName') for region in self._region_states
                if region.get('regionState') == 'ENABLED']

    @property
    def disabled_region_states(self):
        """Disabled region states."""
        return [region.get('regionName') for region in self._region_states
                if region.get('regionState') == 'DISABLED']

    @property
    def payment_cards(self):
        """Payment cards."""
        if self._payment_instrument_ids is None:
            url = 'https://console.aws.amazon.com/billing/rest/ppg-proxy'
            headers = {'x-requested-with': 'XMLHttpRequest',
                       'Operation': 'AWSPaymentPreferenceGateway.Get'}
            payload = {'content': {'Input': {'arn': f'arn:aws:payments:us-east-1:{self.account_id}:'
                                                    f'paymentpreference:PaymentInstrument'},
                                   'Operation': 'com.amazon.aws.payments.gateway.coral.'
                                                'paymentpreference.operations#Get',
                                   'Service': 'com.amazon.aws.payments.gateway.coral.paymentpreference.'
                                              'service#AWSPaymentPreferenceGateway'},
                       'headers': {'Content-Type': 'application/json',
                                   'X-Amz-Date': time.strftime("%a, %d %b %Y %I:%M:%S %Z", time.gmtime()),
                                   'X-Amz-Target': 'AWSPaymentPreferenceGateway.Get'},
                       'region': 'us-east-1'}
            response = self.session.post(url, headers=headers, json=payload)
            if response.status_code == 401:
                raise InvalidCredentials
            if not response.ok:
                self.logger.error(f'Could not retrieve payment instrument id, response: {response.text}')
                raise ServerError
            metadata = response.json().get('Output', {}).get('paymentPreferenceWithMetadata', {})
            self._payment_instrument_ids = [PaymentCard(self, data)
                                            for data in metadata.get('value', {}).get('chargeInstruments', [])]
        return self._payment_instrument_ids

    @property
    def market_place_id(self):
        """Marker place id of account."""
        if self._marketplace_id is None:
            url = 'https://console.aws.amazon.com/billing/home?'
            response = self.session.get(url)
            if response.status_code == 401:
                raise InvalidCredentials
            if not response.ok:
                self.logger.error(f'Could not retrieve market place id, response: {response.text}')
                raise ServerError
            soup = Bfs(response.text, features="html.parser")
            self._marketplace_id = soup.find('input', {'id': 'marketPlace'}).attrs.get('value')
        return self._marketplace_id

    # def get_attribute(self, path):
    #     response = self.session.get(f'{self.rest_api}/{path}')
    #     return response


class PaymentCard(LoggerMixin):
    """Models a payment card."""

    def __init__(self, billing, data):
        self._billing = billing
        self._arn = data.get('arn')
        self._data_ = None

    @property
    def _data(self):
        if self._data_ is None:
            url = f'{self._billing.rest_api}/billingcontactaddress/get'
            parameters = {'marketplaceId': self._billing.market_place_id,
                          'piArn': self._arn}
            response = self._billing.session.get(url, params=parameters)
            if response.status_code == 401:
                raise InvalidCredentials
            if not response.ok:
                self.logger.error(f'Could not retrieve market place id, response: {response.text}')
                raise ServerError
            self._data_ = response.json()
        return self._data_

    @property
    def _address(self):
        return self._data.get('address', {})

    @property
    def address_id(self):
        """Address id."""
        return self._address.get('addressId')

    @property
    def address_line_1(self):
        """First line of the address settings."""
        return self._address.get('addressLine1')

    @property
    def address_line_2(self):
        """Second line of the address settings."""
        return self._address.get('addressLine2')

    @property
    def city(self):
        """City."""
        return self._address.get('city')

    @property
    def company(self):
        """Company."""
        return self._address.get('company')

    @property
    def country_code(self):
        """Country code."""
        return self._address.get('countryCode')

    @property
    def email_address_list(self):
        """Email address list."""
        return self._address.get('emailAddressList', [])

    @property
    def full_name(self):
        """Full name."""
        return self._address.get('fullName')

    @property
    def phone_number(self):
        """Phone number."""
        return self._address.get('phoneNumber')

    @property
    def postal_code(self):
        """Postal code."""
        return self._address.get('postalCode')

    @property
    def state(self):
        """State."""
        return self._address.get('state')

    @property
    def payment_instrument_arn(self):
        """Payment instrument arn."""
        return self._data.get('paymentInstrumentArn')
