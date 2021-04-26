#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: utils.py
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
Main code for utils.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import json
import logging

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''24-12-2020'''
__copyright__ = '''Copyright 2020, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''utils'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class HarParser:
    """Parses a provided har file."""

    def __init__(self, har_file):
        self.data = self._parse(har_file)

    @staticmethod
    def _parse(har_file):
        try:
            data = json.load(open(har_file, 'r'))
        except Exception:
            raise ValueError(f'Could not read or parse file: {har_file}')
        return data

    def _get_service_calls(self, service):
        calls = [entry for entry in self.data['log']['entries']
                 if any(['aws.amazon.com/oauth' in entry['request']['url'],
                         all([f'aws.amazon.com/{service}' in entry['request']['url'],
                              f'aws.amazon.com/{service}/api' not in entry['request']['url']])])]
        return [] if not any([True for entry in calls if service in entry["request"]["url"]]) else calls

    @staticmethod
    def _get_text_from_calls(calls):
        text = ''
        for entry in calls:
            text += f'URL : {entry["request"]["url"]}\n'
            text += '\tRequest Headers :\n'
            for header in entry['request']['headers']:
                text += f'\t\t{header["name"]} : {header["value"]}\n'
            text += "\tRequest Cookies :\n"
            for cookie in entry['request']['cookies']:
                text += f'\t\t{cookie["name"]} : {cookie["value"]}\n'
            text += "\tResponse Headers :\n"
            for header in entry['response']['headers']:
                text += f'\t\t{header["name"]} : {header["value"]}\n'
            text += "\tResponse Cookies :\n"
            for cookie in entry['response']['cookies']:
                text += f'\t\t{cookie["name"]} : {cookie["value"]}\n'
        return text

    def get_communication_for_console(self):
        """Returns a text of the communication of a valid login to console.

        Returns:
            text (str): Returns a text of the communication of a valid login to console.

        """
        return self._get_text_from_calls(self._get_service_calls('console'))

    def get_communication_for_control_tower(self):
        """Returns a text of the communication of a valid login to control tower.

        Returns:
            text (str): Returns a text of the communication of a valid login to control tower.

        """
        return self._get_text_from_calls(self._get_service_calls('controltower'))

    def get_communication_for_sso(self):
        """Returns a text of the communication of a valid login to single sign on.

        Returns:
            text (str): Returns a text of the communication of a valid login to single sign on.

        """
        return self._get_text_from_calls(self._get_service_calls('singlesignon'))

    def get_communication_for_billing(self):
        """Returns a text of the communication of a valid login to billing.

        Returns:
            text (str): Returns a text of the communication of a valid login to billing.

        """
        return self._get_text_from_calls(self._get_service_calls('billing'))

    def render_communication_for_console(self):
        """Prints a text of the communication of a valid login to console.

        Returns:
            None

        """
        print(self.get_communication_for_console())

    def render_communication_for_control_tower(self):
        """Prints a text of the communication of a valid login to control tower.

        Returns:
            None

        """
        print(self.get_communication_for_control_tower())

    def render_communication_for_sso(self):
        """Prints a text of the communication of a valid login to single sign on.

        Returns:
            None

        """
        print(self.get_communication_for_sso())

    def render_communication_for_billing(self):
        """Prints a text of the communication of a valid login to billing.

        Returns:
            None

        """
        print(self.get_communication_for_billing())
