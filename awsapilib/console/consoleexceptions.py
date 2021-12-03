#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: consoleexceptions.py
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
Custom exception code for console.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''30-06-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class NotSolverInstance(Exception):
    """The object provided was not of Solver type."""


class InvalidAuthentication(Exception):
    """The authentication did not succeed."""


class ServerError(Exception):
    """Unknown server error occured."""


class UnableToResolveAccount(Exception):
    """Unable to resolve the account type."""


class UnableToUpdateAccount(Exception):
    """Unable to update the account info."""


class UnableToQueryMFA(Exception):
    """Unable to query the account MFA info."""


class NoMFAProvided(Exception):
    """The account is MFA provided but no MFA serial was provided."""


class UnsupportedMFA(Exception):
    """The MFA enabled is not supported."""


class UnableToRequestResetPassword(Exception):
    """The request to reset password did not work."""


class UnableToResetPassword(Exception):
    """The reset password request did not work."""


class UnableToCreateVirtualMFA(Exception):
    """The attempt to create a virtual mfa failed."""


class UnableToEnableVirtualMFA(Exception):
    """The attempt to create a virtual mfa failed."""


class UnableToDisableVirtualMFA(Exception):
    """The attempt to disable a virtual mfa failed."""


class UnableToGetVirtualMFA(Exception):
    """The attempt to list a virtual mfa failed."""


class VirtualMFADeviceExists(Exception):
    """The device already exists."""
