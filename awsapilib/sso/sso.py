#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: sso.py
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
Main code for sso.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import copy
import logging
import json
from awsapilib.authentication import (Authenticator,
                                      LoggerMixin,
                                      Urls)
from .ssoexceptions import (UnsupportedTarget,
                            NoPermissionSet,
                            NoAccount,
                            NoGroup,
                            NoProfileID,
                            NoUser)
from .entities import (Group,
                       User,
                       Account,
                       PermissionSet)

__author__ = '''Sayantan Khanra <skhanra@schubergphilis.com>, Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''18-05-2020'''
__copyright__ = '''Copyright 2020, Sayantan Khanra, Costas Tyfoxylos'''
__credits__ = ["Sayantan Khanra", "Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Sayantan Khanra, Costas Tyfoxylos'''
__email__ = '''<skhanra@schubergphilis.com>, <ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''sso'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

SUPPORTED_TARGETS = ['GetUserPoolInfo',
                     'SearchGroups',
                     'ProvisionApplicationInstanceForAWSAccount',
                     'ListPermissionSets',
                     'GetApplicationInstanceForAWSAccount',
                     'ProvisionApplicationProfileForAWSAccountInstance',
                     'AssociateProfile',
                     'ListAWSAccountProfiles',
                     'DisassociateProfile',
                     'SearchUsers',
                     'ListMembersInGroup',
                     'ListGroupsForUser',
                     'CreatePermissionSet',
                     'PutPermissionsPolicy',
                     'GetPermissionsPolicy',
                     'ListAccountsWithProvisionedPermissionSet',
                     'UpdatePermissionSet',
                     'listAccounts',
                     'DeletePermissionSet',
                     'DeletePermissionsPolicy',
                     'ProvisionApplicationInstanceForAWSAccount',
                     'ProvisionSAMLProvider']


class Sso(LoggerMixin):  # pylint: disable=too-many-public-methods
    """Models AWS SSO."""

    API_CONTENT_TYPE = 'application/json; charset=UTF-8'
    API_CONTENT_ENCODING = 'amz-1.0'
    DEFAULT_AWS_REGION = 'eu-west-1'

    def __init__(self, arn, region=None):
        self.aws_authenticator = Authenticator(arn, region=region)
        self._urls = Urls(self.aws_region)
        self.session = self._get_authenticated_session()
        self._directory_id = None

    @property
    def relay_state(self):
        """The relay state of the SSO.

        Returns:
            relay_state (str): The relay state of sso.

        """
        return self._urls.regional_relay_state

    @property
    def api_url(self):
        """The url of the api for sso.

        Returns:
            api_url (str): The url of the api for sso.

        """
        return f'{self._urls.regional_single_sign_on}/api'

    @property
    def endpoint_url(self):
        """The url of the api endpoint for sso.

        Returns:
            endpoint_url (str): The url of the api endpoint for sso.

        """
        return f'{self.api_url}/peregrine'

    @property
    def aws_region(self):
        """Aws Console Region.

        Returns:
            region (str): The region of the console.

        """
        return self.aws_authenticator.region

    def get_api_payload(self,  # pylint: disable=too-many-arguments
                        content_string,
                        target,
                        method='POST',
                        params=None,
                        path='/',
                        content_type=None,
                        content_encoding=None,
                        x_amz_target='',
                        region=None):
        """Generates the payload for calling the AWS SSO APIs.

        Returns:
            payload (dict): Returns a deepcopy object of the payload

        """
        target = self._validate_target(target)
        payload = {'contentString': json.dumps(content_string),
                   'headers': {'Content-Type': content_type or self.API_CONTENT_TYPE,
                               'Content-Encoding': content_encoding or self.API_CONTENT_ENCODING,
                               'X-Amz-Target': x_amz_target},
                   'method': method,
                   'operation': target,
                   'params': params or {},
                   'path': path,
                   'region': region or self.DEFAULT_AWS_REGION}
        return copy.deepcopy(payload)

    @staticmethod
    def _validate_target(target):
        if target not in SUPPORTED_TARGETS:
            raise UnsupportedTarget(target)
        return target

    def _get_authenticated_session(self):
        return self.aws_authenticator.get_sso_authenticated_session()

    @property
    def directory_id(self):
        """The external/internal directory id configured with aws sso.

        Returns:
           str: The id of directory configured in SSO

        """
        if self._directory_id is None:
            payload = self.get_api_payload(content_string={},
                                           target='GetUserPoolInfo',
                                           path='/userpool/',
                                           x_amz_target='com.amazonaws.swbup.service.SWBUPService.GetUserPoolInfo',
                                           region=self.aws_region)
            self.logger.debug('Trying to get directory id for sso with payload: %s', payload)
            response = self.session.post(f'{self.api_url}/userpool', json=payload)
            if not response.ok:
                raise ValueError(response.text)
            self._directory_id = response.json().get('DirectoryId')
        return self._directory_id

    @property
    def accounts(self):
        """The aws accounts in sso.

        Returns:
            accounts (generator): The accounts configured in SSO

        """
        headers = {'Content-Type': 'application/x-amz-json-1.1',
                   'Content-Encoding': 'amz-1.0',
                   'X-Amz-Target': 'AWSOrganizationsV20161128.ListAccounts',
                   'X-Amz-User-Agent': 'aws-sdk-js/2.152.0 promise'}
        return self._get_paginated_results(content_payload={},
                                           path='',
                                           target='listAccounts',
                                           amz_target='AWSOrganizationsV20161128.ListAccounts',
                                           region='us-east-1',
                                           object_type=Account,
                                           object_group='Accounts',
                                           url=f'{self.api_url}/organizations',
                                           headers=headers)

    @property
    def users(self):
        """The users configured in SSO.

        Returns:
            users (generator): The users configured in SSO

        """
        content_payload = {'IdentityStoreId': self.directory_id,
                           'MaxResults': 50}
        return self._get_paginated_results(content_payload,
                                           path='identitystore',
                                           target='SearchUsers',
                                           amz_target='com.amazonaws.identitystore.AWSIdentityStoreService.SearchUsers',
                                           region=self.aws_region,
                                           object_type=User,
                                           object_group='Users')

    @property
    def groups(self):
        """The groups configured in SSO.

        Returns:
            groups (generator): The groups configured in SSO

        """
        content_payload = {'SearchString': '*',
                           'SearchAttributes': ['GroupName'],
                           'MaxResults': 100}
        return self._get_paginated_results(content_payload,
                                           path='userpool',
                                           target='SearchGroups',
                                           amz_target='com.amazonaws.swbup.service.SWBUPService.SearchGroups',
                                           region=self.aws_region,
                                           object_type=Group,
                                           object_group='Groups')

    @property
    def permission_sets(self):
        """The permission_sets configured in SSO.

        Returns:
            permission_sets (generator): The permission sets configured in SSO

        """
        return self._get_paginated_results(content_payload={},
                                           path='control',
                                           target='ListPermissionSets',
                                           amz_target='com.amazon.switchboard.service.SWBService.ListPermissionSets',
                                           region=self.aws_region,
                                           object_type=PermissionSet,
                                           object_group='permissionSets',
                                           url=self.endpoint_url,
                                           next_token_marker='marker')

    def get_user_by_name(self, user_name):
        """The user configured in SSO.

        Returns:
            user (User): The User object

        """
        return next((user for user in self.users if user.name == user_name), None)

    def get_user_by_id(self, user_id):
        """The user configured in SSO.

        Returns:
            user (User): The User object

        """
        return next((user for user in self.users if user.id == user_id), None)

    def get_group_by_name(self, group_name):
        """The group configured in SSO.

        Returns:
            group (Group): The Group object

        """
        return next((group for group in self.groups if group.name == group_name), None)

    def get_group_by_id(self, group_id):
        """The group configured in SSO.

        Returns:
            group (Group): The Group object

        """
        return next((group for group in self.groups if group.id == group_id), None)

    def get_account_by_name(self, account_name):
        """The account configured in SSO.

        Returns:
            account (Account): The Account object

        """
        return next((account for account in self.accounts if account.name == account_name), None)

    def get_account_by_id(self, account_id):
        """The account configured in SSO.

        Returns:
            account (Account): The Account object

        """
        return next((account for account in self.accounts if account.id == account_id), None)

    def get_permission_set_by_name(self, permission_set_name):
        """The permission-set configured in SSO.

        Returns:
            permission_set (PermissionSet): The PermissionSet object

        """
        return next((permission_set for permission_set in self.permission_sets
                     if permission_set.name == permission_set_name), None)

    def _provision_application_profile_for_aws_account_instance(self, permission_set_name, account_name):
        method = 'ProvisionApplicationProfileForAWSAccountInstance'
        permission_set = self.get_permission_set_by_name(permission_set_name)
        if not permission_set:
            raise NoPermissionSet(permission_set_name)
        account = self.get_account_by_name(account_name)
        if not account:
            raise NoAccount(account_name)
        payload = self.get_api_payload(content_string={'permissionSetId': permission_set.id,
                                                       'instanceId': account.instance_id},
                                       target=method,
                                       path='/control/',
                                       x_amz_target=f'com.amazon.switchboard.service.SWBService.{method}',
                                       region=self.aws_region)
        self.logger.debug('Trying to provision application profile for aws account with payload: %s', payload)
        response = self.session.post(self.endpoint_url, json=payload)
        if not response.ok:
            raise ValueError(response.text)
        return response.json().get('applicationProfile', {}).get('profileId', '')

    def _get_aws_account_profile_for_permission_set(self, account_name, permission_set_name):
        account = self.get_account_by_name(account_name)
        if not account:
            raise NoAccount(account_name)
        return next((profile for profile in account.associated_profiles
                     if profile.get('name') == permission_set_name), None)

    def associate_group_to_account(self, group_name, account_name, permission_set_name):
        """Associates a group with an account with proper permissions.

        Args:
            group_name: The name of the group to be assigned.
            account_name: Name of the account to which the group will be assigned
            permission_set_name: the Permission Set the group will have on the account

        Returns:
            bool: True or False

        """
        group = self.get_group_by_name(group_name)
        if not group:
            raise NoGroup(group_name)
        account = self.get_account_by_name(account_name)
        if not account:
            raise NoAccount(account_name)
        profile_id = self._provision_application_profile_for_aws_account_instance(permission_set_name, account_name)
        directory_id = self.directory_id
        content_string = {'accessorId': group.id,
                          'accessorType': 'GROUP',
                          'accessorDisplay': {'groupName': group_name},
                          'instanceId': account.instance_id,
                          'profileId': profile_id,
                          'directoryType': 'UserPool',
                          'directoryId': directory_id}
        payload = self.get_api_payload(content_string=content_string,
                                       target='AssociateProfile',
                                       path='/control/',
                                       x_amz_target='com.amazon.switchboard.service.SWBService.AssociateProfile',
                                       region=self.aws_region)
        self.logger.debug('Trying to assign groups to aws account with payload: %s', payload)
        response = self.session.post(self.endpoint_url, json=payload)
        if not response.ok:
            self.logger.error('Received :%s', response.text)
        return response.ok

    def disassociate_group_from_account(self, group_name, account_name, permission_set_name):
        """Disassociates a group with an account with proper permissions.

        Args:
            group_name: The name of the group to be assigned.
            account_name: Name of the account to which the group will be assigned
            permission_set_name: the Permission Set the group will have on the account

        Returns:
            bool: True or False

        """
        group = self.get_group_by_name(group_name)
        if not group:
            raise NoGroup(group_name)
        account = self.get_account_by_name(account_name)
        if not account:
            raise NoAccount(account_name)
        profile_id = self._get_aws_account_profile_for_permission_set(account_name,
                                                                      permission_set_name).get('profileId')
        if not profile_id:
            raise NoProfileID(f'{account_name}:{permission_set_name}')
        content_string = {'accessorId': group.id,
                          'accessorType': 'GROUP',
                          'accessorDisplay': {"groupName": group_name},
                          'instanceId': account.instance_id,
                          'profileId': profile_id,
                          'directoryType': 'UserPool',
                          'directoryId': self.directory_id}
        payload = self.get_api_payload(content_string=content_string,
                                       target='DisassociateProfile',
                                       path='/control/',
                                       x_amz_target='com.amazon.switchboard.service.SWBService.DisassociateProfile',
                                       region=self.aws_region)
        self.logger.debug('Trying to disassociate group from aws account with payload: %s', payload)
        response = self.session.post(self.endpoint_url, json=payload)
        if not response.ok:
            self.logger.error('Received :%s', response.text)
        return response.ok

    def associate_user_to_account(self, user_name, account_name, permission_set_name):
        """Associates an user with an account with proper permissions.

        Args:
            user_name: The name of the user to be assigned.
            account_name: Name of the account to which the user will be assigned
            permission_set_name: the Permission Set the user will have on the account

        Returns:
            bool: True or False

        """
        user = self.get_user_by_name(user_name)
        if not user:
            raise NoUser(user_name)
        account = self.get_account_by_name(account_name)
        if not account:
            raise NoAccount(account_name)
        profile_id = self._provision_application_profile_for_aws_account_instance(permission_set_name, account_name)
        if not profile_id:
            raise NoProfileID(f'{account_name}:{permission_set_name}')
        content_string = {'accessorId': user.id,
                          'accessorType': 'USER',
                          'accessorDisplay': {'userName': user_name,
                                              'firstName': user.first_name,
                                              'last_name': user.last_name,
                                              'windowsUpn': user_name},
                          'instanceId': account.instance_id,
                          'profileId': profile_id,
                          'directoryType': 'UserPool',
                          'directoryId': self.directory_id}
        payload = self.get_api_payload(content_string=content_string,
                                       target='AssociateProfile',
                                       path='/control/',
                                       x_amz_target='com.amazon.switchboard.service.SWBService.AssociateProfile',
                                       region=self.aws_region)
        self.logger.debug('Trying to assign users to aws account with payload: %s', payload)
        response = self.session.post(self.endpoint_url,
                                     json=payload)
        if not response.ok:
            self.logger.error('Received :%s', response.text)
        return response.ok

    def disassociate_user_from_account(self, user_name, account_name, permission_set_name):
        """Disassociates an user with an account with proper permissions.

        Args:
            user_name: The name of the user to be assigned.
            account_name: Name of the account to which the user will be assigned
            permission_set_name: the Permission Set the user will have on the account

        Returns:
            bool: True or False

        """
        user = self.get_user_by_name(user_name)
        if not user:
            raise NoUser(user_name)
        account = self.get_account_by_name(account_name)
        if not account:
            raise NoAccount(account_name)
        profile_id = self._get_aws_account_profile_for_permission_set(account_name,
                                                                      permission_set_name).get('profileId')
        if not profile_id:
            raise NoProfileID(f'{account_name}:{permission_set_name}')
        content_string = {'accessorId': user.id,
                          'accessorType': 'USER',
                          'accessorDisplay': {'userName': user_name,
                                              'firstName': user.first_name,
                                              'last_name': user.last_name,
                                              'windowsUpn': user_name},
                          'instanceId': account.instance_id,
                          'profileId': profile_id,
                          'directoryType': 'UserPool',
                          'directoryId': self.directory_id}
        payload = self.get_api_payload(content_string=content_string,
                                       target='DisassociateProfile',
                                       path='/control/',
                                       x_amz_target='com.amazon.switchboard.service.SWBService.DisassociateProfile',
                                       region=self.aws_region)
        self.logger.debug('Trying to disassociate users from aws account with payload: %s', payload)
        response = self.session.post(self.endpoint_url,
                                     json=payload)
        if not response.ok:
            self.logger.error('Received :%s', response.text)
        return response.ok

    def _get_paginated_results(self,  # pylint: disable=too-many-arguments, too-many-locals
                               content_payload,
                               path,
                               target,
                               amz_target,
                               object_group,
                               object_type=None,
                               region=None,
                               next_token_marker='NextToken',
                               url=None,
                               headers=None):
        payload = self.get_api_payload(content_string=content_payload,
                                       target=target,
                                       path=f'/{path}/' if path else '/',
                                       x_amz_target=amz_target,
                                       region=region)
        if headers:
            payload.update({'headers': headers})
        url = url or f'{self.api_url}/{path}'
        response, next_token = self._get_partial_response(url, payload, next_token_marker)
        for data in response.json().get(object_group, []):
            if object_type:
                yield object_type(self, data)
            else:
                yield data
        while next_token:
            content_string = copy.deepcopy(json.loads(payload.get('contentString')))
            content_string.update({next_token_marker: next_token})
            payload.update({'contentString': json.dumps(content_string)})
            response, next_token = self._get_partial_response(url, payload, next_token_marker)
            for data in response.json().get(object_group, []):
                if object_type:
                    yield object_type(self, data)
                else:
                    yield data

    def _get_partial_response(self, url, payload, next_token_marker):
        response = self.session.post(url, json=payload)
        if not response.ok:
            raise ValueError(response.text)
        next_token = response.json().get(next_token_marker)
        return response, next_token

    def create_permission_set(self, name, description=' ', relay_state=None, ttl='PT2H'):
        """Create a permission_set with a aws defined policy or custom policy.

        Args:
                    name: The name of the permission_set .
                    description: Description for the permission set
                    relay_state: The relay state for the permission set.
                                 https://docs.aws.amazon.com/singlesignon/latest/userguide/howtopermrelaystate.html
                    ttl: session duration
        Returns:
                    PermissionSet: Permission Set object

        """
        content_string = {'permissionSetName': name,
                          'description': description,
                          'relayState': relay_state or self.relay_state,
                          'ttl': ttl}
        payload = self.get_api_payload(content_string=content_string,
                                       target='CreatePermissionSet',
                                       path='/control/',
                                       x_amz_target='com.amazon.switchboard.service.SWBService.CreatePermissionSet',
                                       region=self.aws_region)
        self.logger.debug('Trying to create Permission set with payload: %s', payload)
        response = self.session.post(self.endpoint_url, json=payload)
        if response.ok:
            return PermissionSet(self, response.json().get('permissionSet'))
        return None

    def delete_permission_set(self,
                              name):
        """Delete a permission_set .

        Args:
                name: The name of the permission_set .

        Returns:
                Bool: Status of the deletion

        """
        permission_set_id = self.get_permission_set_by_name(name).id
        content_string = {'permissionSetId': permission_set_id}
        payload = self.get_api_payload(content_string=content_string,
                                       target='DeletePermissionSet',
                                       path='/control/',
                                       x_amz_target='com.amazon.switchboard.service.SWBService.DeletePermissionSet',
                                       region=self.aws_region
                                       )
        self.logger.debug('Trying to delete Permission set...')

        response = self.session.post(self.endpoint_url,
                                     json=payload)
        if not response.ok:
            self.logger.error('Received :%s', response.text)
        return response.ok
