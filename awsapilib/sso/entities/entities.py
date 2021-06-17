#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: entities.py
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
Main code for entities.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import logging
import json

from awsapilib.authentication import LoggerMixin

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
LOGGER_BASENAME = '''entities'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class Entity(LoggerMixin):  # pylint: disable=too-few-public-methods
    """The core entity."""

    def __init__(self, sso_instance, data):
        self._sso = sso_instance
        self._data = self._parse_data(data)

    def _parse_data(self, data):
        if not isinstance(data, dict):
            self.logger.error(f'Invalid data received :{data}')
            data = {}
        return data


class Group(Entity):
    """Models the group object of AWS SSO."""

    def __init__(self, sso_instance, data):
        super().__init__(sso_instance, data)
        self.url = f'{sso_instance.api_url}/userpool'

    @property
    def id(self):  # pylint: disable=invalid-name
        """The id of the group.

        Returns:
            id (str) : The id of the group

        """
        return self._data.get('GroupId')

    @property
    def name(self):
        """The name of the group.

        Returns:
            name (str) : The name of the group

        """
        return self._data.get('GroupName', '')

    @property
    def description(self):
        """The description of the group.

        Returns:
            description (str) : The description of the group

        """
        return self._data.get('Description', '')

    @property
    def users(self):
        """The users in the group.

        Returns:
            users (list): The users part of the group

        """
        content_payload = {'GroupId': self.id,
                           'MaxResults': 100}
        target = 'com.amazonaws.swbup.service.SWBUPService.ListMembersInGroup'
        for user in self._sso._get_paginated_results(content_payload=content_payload,  # pylint: disable=protected-access
                                                     path='userpool',
                                                     target='ListMembersInGroup',
                                                     amz_target=target,
                                                     object_group='Members',
                                                     url=self.url):
            yield self._sso.get_user_by_id(user.get('Id'))


class Account(Entity):
    """Models the Account object of AWS SSO."""

    @property
    def url(self):
        """Url for the account.

        Returns:
            url (str): The url of the account

        """
        return self._sso.endpoint_url

    @property
    def name(self):
        """The name of the application.

        Returns:
            name (str): The name of the application

        """
        return self._data.get('Name')

    @property
    def email(self):
        """The name of the application.

        Returns:
            email (str) : The name of the application

        """
        return self._data.get('Email')

    @property
    def id(self):  # pylint: disable=invalid-name
        """The id of the application.

        Returns:
            id (str): The id of the application

        """
        return self._data.get('Id')

    @property
    def arn(self):
        """The arn of the application.

        Returns:
            arn (str): The arn of the application

        """
        return self._data.get('Arn')

    @property
    def status(self):
        """The status of the application.

        Returns:
            status (str): The status of the application

        """
        return self._data.get('Status')

    def provision_saml_provider(self):
        """Creates the SAMl provider.

        Returns:
            arn (str): The arn of the SAMl provider

        """
        target = 'com.amazon.switchboard.service.SWBService.ProvisionSAMLProvider'
        payload = self._sso.get_api_payload(content_string={'applicationInstanceId': self.instance_id
                                                            },
                                            target='ProvisionSAMLProvider',
                                            path='/control/',
                                            x_amz_target=target)
        self.logger.debug('Trying to create saml provider for aws account with payload: %s', payload)
        response = self._sso.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error(response.text)
            return {}
        return response.json()

    @property
    def instance_id(self):
        """The instance id of the Account.

        Returns:
            instance_id (str): The instance id of the account

        """
        instance_id = self._retrieve_instance_id()
        if not instance_id:
            instance_id = self._provision_application_instance_for_aws_account()
        return instance_id

    def _provision_application_instance_for_aws_account(self):
        target = 'com.amazon.switchboard.service.SWBService.ProvisionApplicationInstanceForAWSAccount'
        payload = self._sso.get_api_payload(content_string={'accountId': self.id,
                                                            'accountEmail': self.email,
                                                            'accountName': self.name
                                                            },
                                            target='ProvisionApplicationInstanceForAWSAccount',
                                            path='/control/',
                                            x_amz_target=target)
        self.logger.debug('Trying to get instance id for aws account with payload: %s', payload)
        response = self._sso.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error(response.text)
            return None
        return response.json().get('applicationInstance', {}).get('instanceId', None)

    def _retrieve_instance_id(self):
        account_id = self.id
        target = 'com.amazon.switchboard.service.SWBService.GetApplicationInstanceForAWSAccount'
        payload = self._sso.get_api_payload(content_string={'awsAccountId': account_id},
                                            target='GetApplicationInstanceForAWSAccount',
                                            path='/control/',
                                            x_amz_target=target)
        self.logger.debug('Trying to get instance id for aws account with payload: %s', payload)
        response = self._sso.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error(response.text)
            return None
        return response.json().get('applicationInstance', {}).get('instanceId', None)

    @property
    def associated_profiles(self):
        """The associated profiles with the Account.

        Returns:
            associated_profiles (list): The profiles associated with the Account

        """
        target = 'com.amazon.switchboard.service.SWBService.ListAWSAccountProfiles'
        payload = self._sso.get_api_payload(content_string={'instanceId': self.instance_id},
                                            target='ListAWSAccountProfiles',
                                            path='/control/',
                                            x_amz_target=target)
        self.logger.debug('Trying to provision application profile for aws account with payload: %s', payload)
        response = self._sso.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error(response.text)
            return []
        return response.json().get('profileList', [])


class User(Entity):
    """Models the user object of SSO."""

    @property
    def url(self):
        """Url for the user.

        Returns:
            url (str): The url for the user

        """
        return f'{self._sso.api_url}/userpool'

    @property
    def status(self):
        """The status of the user.

        Returns:
            status (str): The status of the user

        """
        return self._data.get('Active')

    @property
    def created_at(self):
        """The date and time of the users's activation.

        Returns:
            created_at (datetime): The datetime object of when the user was activated

        """
        return self._data.get('Meta', {}).get('CreatedAt')

    @property
    def updated_at(self):
        """The date and time of the users's status change.

        Returns:
            updated_at (datetime): The datetime object of when the user had last changed status

        """
        return self._data.get('Meta', {}).get('UpdatedAt')

    @property
    def emails(self):
        """The date and time of the users's last password change.

        Returns:
            emails (datetime): The datetime object of when the user last changed password

        """
        return self._data.get('UserAttributes').get('emails', {}).get('ComplexListValue', '')

    @property
    def _name(self):
        return self._data.get('UserAttributes').get('name', {}).get('ComplexValue', {})

    @property
    def first_name(self):
        """The first name of the user.

        Returns:
            first_name (str): The first name of the user

        """
        return self._name.get('givenName', {}).get('StringValue', '')

    @property
    def last_name(self):
        """The last name of the user.

        Returns:
            last_name (str): The last name of the user

        """
        return self._name.get('familyName', {}).get('StringValue', '')

    @property
    def id(self):  # pylint: disable=invalid-name
        """The manager of the user.

        Returns:
            id (str): The manager of the user

        """
        return self._data.get('UserId')

    @property
    def name(self):
        """The manager of the user.

        Returns:
            name (str): The manager of the user

        """
        return self._data.get('UserName')

    @property
    def display_name(self):
        """The display name of the user.

        Returns:
            display_name (str): The display name of the user

        """
        return self._data.get('UserAttributes', {}).get('displayName', {}).get('StringValue')

    @property
    def groups(self):
        """The groups associated with the user.

        Returns:
            groups (list): The groups associated with the user

        """
        content_payload = {'UserId': self.id,
                           'MaxResults': 100}
        target = 'com.amazonaws.swbup.service.SWBUPService.ListGroupsForUser'
        for group in self._sso._get_paginated_results(content_payload=content_payload,  # pylint: disable=protected-access
                                                      path='userpool',
                                                      target='ListGroupsForUser',
                                                      amz_target=target,
                                                      object_group='Groups',
                                                      url=self.url):
            yield self._sso.get_group_by_id(group.get('GroupId'))


class PermissionSet(Entity):
    """Models the permission set object of SSO."""

    @property
    def url(self):
        """Url of the permission set.

        Returns:
            url (str): The url of the permission set

        """
        return self._sso.endpoint_url

    @property
    def description(self):
        """The description of the permission set.

        Returns:
            description (str): The description of the permission set

        """
        return self._data.get('Description')

    @property
    def id(self):  # pylint: disable=invalid-name
        """The id of the permission set.

        Returns:
            id (str): The id of the permission set

        """
        return self._data.get('Id')

    @property
    def name(self):
        """The name of the permission set.

        Returns:
            name (str): The name of the permission set

        """
        return self._data.get('Name')

    @property
    def ttl(self):
        """The ttl of the permission set.

        Returns:
            ttl (str): The ttl of the permission set

        """
        return self._data.get('ttl')

    @property
    def creation_date(self):
        """The creation date of the permission set.

        Returns:
            creation_date (str): The creation date of the permission set

        """
        return self._data.get('CreationDate')

    @property
    def relay_state(self):
        """The relay_state of the permission_set.

        Returns:
            relay_state (str): The relayState of the permission_set

        """
        return self._data.get('relayState')

    @property
    def permission_policy(self):
        """The permission policy of the permission_set.

        Returns:
            permission_policy (dict): The permission policy of the permission_set

        """
        target = 'com.amazon.switchboard.service.SWBService.GetPermissionsPolicy'
        content_string = {'permissionSetId': self.id}
        payload = self._sso.get_api_payload(content_string=content_string,
                                            target='GetPermissionsPolicy',
                                            path='/control/',
                                            x_amz_target=target)
        self.logger.debug('Getting permission policy for permission_set with payload of %s:', payload)
        response = self._sso.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error(response.text)
            return None
        return response.json()

    @property
    def provisioned_accounts(self):
        """The provisioned accounts with the permission set.

        Returns:
            list: Accounts provisioned with the permission set

        """
        content_payload = {'permissionSetId': self.id,
                           'onlyOutOfSync': 'false'}
        target = 'com.amazon.switchboard.service.SWBService.ListAccountsWithProvisionedPermissionSet'
        for account_id in self._sso._get_paginated_results(content_payload=content_payload,  # pylint: disable=protected-access
                                                           path='control',
                                                           target='ListAccountsWithProvisionedPermissionSet',
                                                           amz_target=target,
                                                           object_group='accountIds',
                                                           next_token_marker='marker',
                                                           url=self._sso.endpoint_url):
            yield self._sso.get_account_by_id(account_id)

    def assign_custom_policy_to_permission_set(self, policy_document):
        """Assign Custom policy to a permission_set.

        Args:
            permission_set_name: The name of the permission_set .
            policy_document: The policy for the permission_set
        Returns:
            Bool:  True or False

        """
        content_string = {'permissionSetId': self.id,
                          'policyDocument': json.dumps(policy_document)}
        target = 'com.amazon.switchboard.service.SWBService.PutPermissionsPolicy'
        payload = self._sso.get_api_payload(content_string=content_string,
                                            target='PutPermissionsPolicy',
                                            path='/control/',
                                            x_amz_target=target)
        self.logger.debug('Assigning custom policy to permission set with payload %s:', payload)
        response = self._sso.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error(response.text)
        else:
            if self.provisioned_accounts:  # pylint: disable=using-constant-test
                for account in self.provisioned_accounts:
                    self.logger.debug('Updating associated account %s', account.name)
                    self._sso._provision_application_profile_for_aws_account_instance(self.name, account.name)  # pylint: disable=protected-access
        return response.ok

    def delete_custom_policy_from_permission_set(self):
        """Assign Custom policy to a permission_set.

        Returns:
            Bool:  True or False

        """
        content_string = {'permissionSetId': self.id}
        target = 'com.amazon.switchboard.service.SWBService.DeletePermissionsPolicy'
        payload = self._sso.get_api_payload(content_string=content_string,
                                            target='DeletePermissionsPolicy',
                                            path='/control/',
                                            x_amz_target=target)
        response = self._sso.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error(response.text)
        else:
            if self.provisioned_accounts:  # pylint: disable=using-constant-test
                for account in self.provisioned_accounts:
                    self.logger.debug('Updating associated account %s', account.name)
                    self._sso._provision_application_profile_for_aws_account_instance(self.name, account.name)  # pylint: disable=protected-access
        return response.ok

    def update(self, description=' ', relay_state='', ttl=''):
        """The relayState of the permission_set.

        Args:
            description: Description for the permission set
            relay_state: The relay state for the permission set.
                                 https://docs.aws.amazon.com/singlesignon/latest/userguide/howtopermrelaystate.html
            ttl: session duration

        Returns:
            bool: True or False

        """
        content_string = {'permissionSetId': self.id,
                          'description': description if description != ' ' else self.description,
                          'ttl': ttl if ttl else self.ttl,
                          'relayState': relay_state if relay_state else self.relay_state}
        target = 'com.amazon.switchboard.service.SWBService.UpdatePermissionSet'
        payload = self._sso.get_api_payload(content_string=content_string,
                                            target='UpdatePermissionSet',
                                            path='/control/',
                                            x_amz_target=target)
        self.logger.debug('Posting to url %s payload of %s:', self.url, payload)
        response = self._sso.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error(response.text)
        return response.ok
