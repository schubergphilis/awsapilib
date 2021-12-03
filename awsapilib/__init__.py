#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: __init__.py
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
awsapilib package.

Import all parts from awsapilib here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""
from ._version import __version__
from .authentication import LoggerMixin, Authenticator
from .controltower import ControlTower
from .billing import Billing
from .sso import Sso
from .cloudformation import Cloudformation
from .console import AccountManager, PasswordManager

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''26-04-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is to 'use' the module(s), so lint doesn't complain
assert __version__

assert LoggerMixin
assert Authenticator
assert ControlTower
assert Billing
assert Sso
assert Cloudformation
assert AccountManager
assert PasswordManager
