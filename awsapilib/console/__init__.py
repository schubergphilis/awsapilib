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
console package.

Import all parts from console here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""

from .console import AccountManager, PasswordManager
from .consoleexceptions import (NotSolverInstance,
                                InvalidAuthentication,
                                InvalidCaptcha,
                                ServerError,
                                UnableToResolveAccount,
                                UnableToUpdateAccount,
                                UnableToQueryMFA,
                                NoMFAProvided,
                                UnsupportedMFA,
                                UnableToRequestResetPassword,
                                UnableToResetPassword,
                                UnableToCreateVirtualMFA,
                                UnableToEnableVirtualMFA,
                                UnableToDisableVirtualMFA,
                                UnableToGetVirtualMFA,
                                VirtualMFADeviceExists)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''30-06-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is to 'use' the module(s), so lint doesn't complain

assert AccountManager
assert PasswordManager

assert NotSolverInstance
assert InvalidAuthentication
assert InvalidCaptcha
assert ServerError
assert UnableToResolveAccount
assert UnableToUpdateAccount
assert UnableToQueryMFA
assert NoMFAProvided
assert UnsupportedMFA
assert UnableToRequestResetPassword
assert UnableToResetPassword
assert UnableToCreateVirtualMFA
assert UnableToEnableVirtualMFA
assert UnableToDisableVirtualMFA
assert UnableToGetVirtualMFA
assert VirtualMFADeviceExists
