#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: controltowerexceptions.py
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
Custom exception code for controltower.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''18-02-2020'''
__copyright__ = '''Copyright 2020, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class UnsupportedTarget(Exception):
    """The target call is not supported by the current implementation."""


class OUCreating(Exception):
    """The organizational unit is still under creation and cannot be used."""


class NoServiceCatalogAccess(Exception):
    """There is no access to service catalog."""


class NonExistentSCP(Exception):
    """The SCP requested does not exist."""


class NoSuspendedOU(Exception):
    """The suspended ou has not been created."""


class ServiceCallFailed(Exception):
    """The call to the service has failed."""


class ControlTowerBusy(Exception):
    """The control tower is already executing some action."""


class ControlTowerNotDeployed(Exception):
    """The control tower is deployed at all."""


class PreDeployValidationFailed(Exception):
    """The pre deployment validation failed."""


class EmailCheckFailed(Exception):
    """Checking of the email was not possible."""


class EmailInUse(Exception):
    """The email provided is already in use and cannot be used to deploy an account."""


class UnavailableRegion(Exception):
    """The region or regions provided to control tower to deploy in are not available."""


class RoleCreationFailure(Exception):
    """Unable to create the required roles for the deployment of control tower, manual clean up is required."""
