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
   https://google.github.io/styleguide/pyguide.html
"""
from awsapilib.authentication import (AssumedRoleAuthenticator,
                                      RootAuthenticator,
                                      AwsSession,
                                      CONSOLE_SOLVER,
                                      InvalidArn,
                                      XXTEAException,
                                      InvalidMetadata,
                                      InvalidDecryption,
                                      EncryptionFailure,
                                      DecryptionFailure,
                                      NoSigninTokenReceived,
                                      InvalidCredentials,
                                      ExpiredCredentials,
                                      UnexpectedResponse,
                                      NotSolverInstance,
                                      InvalidAuthentication,
                                      UnableToResolveAccount,
                                      UnableToUpdateAccount,
                                      UnableToQueryMFA,
                                      NoMFAProvided,
                                      UnsupportedMFA,
                                      InvalidCaptcha,
                                      AuthenticationUnexpectedResponse)
from awsapilib.billing import (Billing,
                               InvalidCurrency,
                               NonEditableSetting,
                               BillingUnexpectedResponse,
                               IAMAccessDenied,
                               InvalidCountryCode)
from awsapilib.captcha import (Solver,
                               Iterm,
                               Terminal,
                               CaptchaError,
                               UnsupportedTerminal,
                               Captcha2,
                               InvalidOrNoBalanceApiToken)
from awsapilib.cloudformation import Cloudformation, CloudformationUnexpectedResponse
from awsapilib.console import (AccountManager,
                               PasswordManager,
                               UnableToResetPassword,
                               UnableToCreateVirtualMFA,
                               UnableToEnableVirtualMFA,
                               UnableToDisableVirtualMFA,
                               UnableToGetVirtualMFA,
                               UnableToRequestResetPassword,
                               VirtualMFADeviceExists)
from awsapilib.controltower import (ControlTower,
                                    UnsupportedTarget,
                                    OUCreating,
                                    NoServiceCatalogAccess,
                                    NonExistentSCP,
                                    NoSuspendedOU,
                                    ServiceCallFailed,
                                    ControlTowerBusy,
                                    ControlTowerNotDeployed,
                                    PreDeployValidationFailed,
                                    EmailCheckFailed,
                                    EmailInUse,
                                    UnavailableRegion,
                                    RoleCreationFailure,
                                    NoActiveArtifactRetrieved,
                                    NonExistentOU,
                                    InvalidParentHierarchy)
# from awsapilib.sso import (Sso,
#                            UnsupportedTarget,
#                            NoPermissionSet,
#                            NoAccount,
#                            NoGroup,
#                            NoProfileID,
#                            NoUser)
from ._version import __version__

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

assert AccountManager
assert PasswordManager
assert UnableToResetPassword
assert UnableToCreateVirtualMFA
assert UnableToEnableVirtualMFA
assert UnableToDisableVirtualMFA
assert UnableToGetVirtualMFA
assert UnableToRequestResetPassword
assert VirtualMFADeviceExists

assert Solver
assert Iterm
assert Terminal
assert CaptchaError
assert UnsupportedTerminal
assert Captcha2
assert InvalidOrNoBalanceApiToken

assert ControlTower
assert UnsupportedTarget
assert OUCreating
assert NoServiceCatalogAccess
assert NonExistentSCP
assert NoSuspendedOU
assert ServiceCallFailed
assert ControlTowerBusy
assert ControlTowerNotDeployed
assert PreDeployValidationFailed
assert EmailCheckFailed
assert EmailInUse
assert UnavailableRegion
assert RoleCreationFailure
assert NoActiveArtifactRetrieved
assert NonExistentOU
assert InvalidParentHierarchy

assert Cloudformation
assert CloudformationUnexpectedResponse

assert Billing
assert InvalidCurrency
assert NonEditableSetting
assert BillingUnexpectedResponse
assert IAMAccessDenied
assert InvalidCountryCode

assert AssumedRoleAuthenticator
assert RootAuthenticator
assert AwsSession
assert CONSOLE_SOLVER
assert InvalidArn
assert XXTEAException
assert InvalidMetadata
assert InvalidDecryption
assert EncryptionFailure
assert DecryptionFailure
assert NoSigninTokenReceived
assert InvalidCredentials
assert ExpiredCredentials
assert UnexpectedResponse
assert NotSolverInstance
assert InvalidAuthentication
assert UnableToResolveAccount
assert UnableToUpdateAccount
assert UnableToQueryMFA
assert NoMFAProvided
assert UnsupportedMFA
assert InvalidCaptcha
assert AuthenticationUnexpectedResponse

# assert Sso
# assert UnsupportedTarget
# assert NoPermissionSet
# assert NoAccount
# assert NoGroup
# assert NoProfileID
# assert NoUser
