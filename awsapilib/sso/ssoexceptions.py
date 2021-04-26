#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: ssoexceptions.py
#
# Copyright 2020 Sayantan Khanra, Costas Tyfoxylos
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
Custom exception code for sso.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

__author__ = '''Sayantan Khanra <skhanra@schubergphilis.com>, Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''18-05-2020'''
__copyright__ = '''Copyright 2020, Sayantan Khanra, Costas Tyfoxylos'''
__credits__ = ["Sayantan Khanra", "Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Sayantan Khanra, Costas Tyfoxylos'''
__email__ = '''<skhanra@schubergphilis.com>, <ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class UnsupportedTarget(Exception):
    """The target call is not supported by the current implementation."""


class NoPermissionSet(Exception):
    """The permission set does not exist."""


class NoAccount(Exception):
    """The account does not exist."""


class NoGroup(Exception):
    """The group does not exist."""


class NoProfileID(Exception):
    """The permission set is not associated with the account."""


class NoUser(Exception):
    """The user does not exist."""
