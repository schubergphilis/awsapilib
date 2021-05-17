#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: __init__.py
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
resources module.

Import all parts from resources here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""

from time import sleep

from awsapilib.authentication import LoggerMixin
from awsapilib.controltower.controltowerexceptions import (NonExistentSCP,
                                                           ControlTowerBusy,
                                                           NoSuspendedOU)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''18-02-2020'''
__copyright__ = '''Copyright 2020, Costas Tyfoxylos'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class AccountFactory:  # pylint: disable=too-few-public-methods, too-many-instance-attributes
    """Models the account factory data of service catalog."""

    def __init__(self, service_catalog_client, data):
        self._service_catalog = service_catalog_client
        self._data = data
        self.has_default_path = self._data.get('HasDefaultPath')
        self.id = self._data.get('Id')  # pylint: disable=invalid-name
        self.name = self._data.get('Name')
        self.owner = self._data.get('Owner')
        self.product_id = self._data.get('ProductId')
        self.short_description = self._data.get('ShortDescription')
        self.type = self._data.get('Type')


class ServiceControlPolicy:
    """Models the account factory data of service catalog."""

    def __init__(self, data):
        self._data = data

    @property
    def arn(self):
        """Arn."""
        return self._data.get('Arn')

    @property
    def aws_managed(self):
        """Aws Managed."""
        return self._data.get('AwsManaged')

    @property
    def description(self):
        """Description."""
        return self._data.get('Description')

    @property
    def id(self):  # pylint: disable=invalid-name
        """Id."""
        return self._data.get('Id')

    @property
    def name(self):
        """Name."""
        return self._data.get('Name')

    @property
    def type(self):
        """Type."""
        return self._data.get('Type')


class GuardRail(LoggerMixin):
    """Models the guard rail data."""

    def __init__(self, control_tower, data):
        self.control_tower = control_tower
        self._data_ = data

    @property
    def _data(self):
        """The data of the guard rail as returned by the api."""
        return self._data_

    @property
    def behavior(self):
        """Behavior."""
        return self._data_.get('Behavior')

    @property
    def category(self):
        """Category."""
        return self._data_.get('Category')

    @property
    def description(self):
        """Description."""
        return self._data_.get('Description')

    @property
    def display_name(self):
        """DisplayName."""
        return self._data_.get('DisplayName')

    @property
    def name(self):
        """Name."""
        return self._data_.get('Name')

    @property
    def provider(self):
        """Provider."""
        return self._data_.get('Provider')

    @property
    def regional_preference(self):
        """Regional preference."""
        return self._data_.get('RegionalPreference')

    @property
    def type(self):
        """Type."""
        return self._data_.get('Type')

    @property
    def compliancy_status(self):
        """Compliancy status."""
        payload = self.control_tower._get_api_payload(content_string={'GuardrailName': self.name},  # pylint: disable=protected-access
                                                      target='getGuardrailComplianceStatus')
        self.logger.debug('Trying to get the compliancy status with payload "%s"', payload)
        response = self.control_tower.session.post(self.control_tower.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to get the drift message of the landing zone with response status "%s" and '
                              'response text "%s"',
                              response.status_code, response.text)
            return None
        return response.json().get('ComplianceStatus')


class CoreAccount:
    """Models the core landing zone account data."""

    def __init__(self, control_tower, account_label, data):
        self.control_tower = control_tower
        self._label = account_label
        self._data_ = data

    @property
    def _data(self):
        """The data of the account as returned by the api."""
        return self._data_

    @property
    def label(self):
        """Account label."""
        return self._label

    @property
    def email(self):
        """Email."""
        return self._data_.get('AccountEmail')

    @property
    def id(self):  # pylint: disable=invalid-name
        """Id."""
        return self._data_.get('AccountId')

    @property
    def core_resource_mappings(self):
        """Core resource mappings."""
        return self._data_.get('CoreResourceMappings')

    @property
    def stack_set_arn(self):
        """Stack set arn."""
        return self._data_.get('StackSetARN')


class ControlTowerAccount(LoggerMixin):  # pylint: disable=too-many-public-methods
    """Models the account data."""

    def __init__(self, control_tower, data, info_polling_interval=30):
        self.control_tower = control_tower
        self.service_catalog = control_tower.service_catalog
        self.organizations = control_tower.organizations
        self._data_ = data
        self._service_catalog_data_ = None
        self._record_data_ = None
        self._info_polling_interval = info_polling_interval

    @property
    def _data(self):
        """The data of the account as returned by the api."""
        return self._data_

    @property
    def _service_catalog_data(self):
        if self._service_catalog_data_ is None:
            data = self.service_catalog.search_provisioned_products(Filters={'SearchQuery': [f'physicalId:{self.id}']})
            if not data.get('TotalResultsCount'):
                self._service_catalog_data_ = {}
            else:
                self._service_catalog_data_ = data.get('ProvisionedProducts', [{}]).pop()
        return self._service_catalog_data_

    @property
    def _record_data(self):
        if self._record_data_ is None:
            if not self.last_record_id:
                self._record_data_ = {}
            else:
                self._record_data_ = self.service_catalog.describe_record(Id=self.last_record_id)
        return self._record_data_

    @property
    def email(self):
        """Email."""
        return self._data_.get('AccountEmail')

    @property
    def id(self):  # pylint: disable=invalid-name
        """Id."""
        return self._data_.get('AccountId')

    @property
    def name(self):
        """Name."""
        return self._data_.get('AccountName')

    @property
    def arn(self):
        """Arn."""
        return self._data_.get('Arn')

    @property
    def owner(self):
        """Owner."""
        return self._data_.get('Owner')

    @property
    def provision_state(self):
        """Provision state."""
        return self._data_.get('ProvisionState')

    @property
    def status(self):
        """Status."""
        return self._data_.get('Status')

    @property
    def landing_zone_version(self):
        """Landing zone version."""
        return self._data_.get('DeployedLandingZoneVersion')

    @property
    def has_available_update(self):
        """If the account is behind the landing zone version."""
        if self.provision_state == 'PROVISION_FAILED':
            return False
        return float(self.landing_zone_version) < float(self.control_tower.landing_zone_version)

    @property
    def guardrail_compliance_status(self):
        """Retrieves the guardrail compliancy status for the account.

        Returns:
            status (str): COMPLIANT|NON COMPLIANT

        """
        payload = self.control_tower._get_api_payload(content_string={'AccountId': self.id},  # pylint: disable=protected-access
                                                      target='getGuardrailComplianceStatus')
        response = self.control_tower.session.post(self.control_tower.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to get compliancy status from api.')
            return False
        return response.json().get('ComplianceStatus')

    @property
    def organizational_unit(self):
        """Organizational Unit."""
        return self.control_tower.get_organizational_unit_by_id(self._data_.get('ParentOrganizationalUnitId'))

    @property
    def stack_arn(self):
        """Stack Arn."""
        return self._service_catalog_data.get('Arn')

    @property
    def created_time(self):
        """Created Time."""
        return self._service_catalog_data.get('CreatedTime')

    @property
    def service_catalog_id(self):
        """Service Catalog ID."""
        return self._service_catalog_data.get('Id')

    @property
    def idempotency_token(self):
        """Idempotency Token."""
        return self._service_catalog_data.get('IdempotencyToken')

    @property
    def last_record_id(self):
        """Last Record ID."""
        return self._service_catalog_data.get('LastRecordId')

    @property
    def physical_id(self):
        """Physical ID."""
        return self._service_catalog_data.get('PhysicalId')

    @property
    def service_catalog_product_id(self):
        """Service catalog product ID."""
        return self._service_catalog_data.get('ProductId')

    @property
    def provisioning_artifact_id(self):
        """Provisioning artifact ID."""
        return self._service_catalog_data.get('ProvisioningArtifactId')

    @property
    def service_catalog_tags(self):
        """Service catalog tags."""
        return self._service_catalog_data.get('Tags')

    @property
    def service_catalog_type(self):
        """Service catalog type."""
        return self._service_catalog_data.get('Type')

    @property
    def service_catalog_status(self):
        """Service catalog status."""
        return self._service_catalog_data.get('Status')

    @property
    def service_catalog_user_arn(self):
        """Service catalog user arn."""
        return self._service_catalog_data.get('UserArn')

    @property
    def user_arn_session(self):
        """User arn session."""
        return self._service_catalog_data.get('UserArnSession')

    def _refresh(self):
        self._data_ = self.control_tower.get_account_by_id(self.id)._data  # pylint: disable=protected-access
        self._record_data_ = None
        self._service_catalog_data_ = None

    def _get_record_entry(self, output_key):
        return next((entry for entry in self._record_data.get('RecordOutputs', [])
                     if entry.get('OutputKey', '') == output_key), {})

    @property
    def sso_user_email(self):
        """SSO user email."""
        return self._get_record_entry(output_key='SSOUserEmail').get('OutputValue')

    @property
    def sso_user_portal(self):
        """SSO user portal."""
        return self._get_record_entry(output_key='SSOUserPortal').get('OutputValue')

    def detach_service_control_policy(self, name):
        """Detaches a Service Control Policy from the account.

        Args:
            name (str): The name of the SCP to detach

        Returns:
            result (bool): True on success, False otherwise.

        """
        return self._action_service_control_policy('detach', name)

    def attach_service_control_policy(self, name):
        """Attaches a Service Control Policy to the account.

        Args:
            name (str): The name of the SCP to attach

        Returns:
            result (bool): True on success, False otherwise.

        """
        return self._action_service_control_policy('attach', name)

    def _action_service_control_policy(self, action, scp_name):
        scp = self.control_tower.get_service_control_policy_by_name(scp_name)
        if not scp:
            raise NonExistentSCP(scp_name)
        response = getattr(self.organizations, f'{action}_policy')(PolicyId=scp.id, TargetId=self.id)
        if not response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
            self.logger.error('Failed to %s SCP "%s" to account with response "%s"', action, scp.name, response)
            return False
        self.logger.debug('Successfully %sed SCP "%s" to account', action, scp.name)
        return True

    def _terminate(self):
        """Terminates an account that is in error.

        Returns:
            response (dict): The response from the api of the termination request.

        """
        return self.service_catalog.terminate_provisioned_product(ProvisionedProductId=self.service_catalog_id)

    def delete(self, suspended_ou_name=None):
        """Delete."""
        if not suspended_ou_name:
            return self._terminate()
        suspended_ou = self.control_tower.get_organizational_unit_by_name(suspended_ou_name)
        if not suspended_ou:
            raise NoSuspendedOU(suspended_ou_name)
        self._terminate()
        while self.control_tower.busy:
            self.logger.debug('Waiting for control tower to terminate the account...')
            sleep(self._info_polling_interval)
        self.logger.debug('Moving account from root OU to %s', suspended_ou_name)
        self.organizations.move_account(AccountId=self.id,
                                        SourceParentId=self.control_tower.root_ou.id,
                                        DestinationParentId=suspended_ou.id)
        self.logger.debug('Attaching SCP %s to account', suspended_ou_name)
        self.attach_service_control_policy(suspended_ou_name)
        self.logger.debug('Detaching full access SCP from account')
        self.detach_service_control_policy('FullAWSAccess')
        return True

    def update(self):
        """Updates the account in service catalog.

        Returns:
            True if the call succeeded False otherwise

        """
        if not self.has_available_update:
            return True
        if self.control_tower.busy:
            raise ControlTowerBusy
        arguments = {'ProductId': self.control_tower._account_factory.product_id,  # pylint: disable=protected-access
                     'ProvisionedProductName': self.name,
                     'ProvisioningArtifactId': self.control_tower._active_artifact.get('Id'),  # pylint: disable=protected-access
                     'ProvisioningParameters': [{'Key': 'AccountName',
                                                 'Value': self.name,
                                                 'UsePreviousValue': True},
                                                {'Key': 'AccountEmail',
                                                 'Value': self.email,
                                                 'UsePreviousValue': True},
                                                {'Key': 'SSOUserFirstName',
                                                 'Value': 'Control',
                                                 'UsePreviousValue': True},
                                                {'Key': 'SSOUserLastName',
                                                 'Value': 'Tower',
                                                 'UsePreviousValue': True},
                                                {'Key': 'SSOUserEmail',
                                                 'Value': self.email,
                                                 'UsePreviousValue': True},
                                                {'Key': 'ManagedOrganizationalUnit',
                                                 'Value': self.organizational_unit.name,
                                                 'UsePreviousValue': True}]}
        response = self.service_catalog.update_provisioned_product(**arguments)
        return response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200


class OrganizationsOU:
    """Model the data of an Organizations managed OU."""

    def __init__(self, data):
        self._data = data

    @property
    def id(self):  # pylint: disable=invalid-name
        """The id of the OU."""
        return self._data.get('Id')

    @property
    def name(self):
        """The name of the OU."""
        return self._data.get('Name')

    @property
    def arn(self):
        """The arn of the OU."""
        return self._data.get('Arn')


class ControlTowerOU:
    """Model the data of a Control Tower managed OU."""

    def __init__(self, control_tower, data):
        self.control_tower = control_tower
        self._data = data

    @property
    def create_date(self):
        """The date the ou was created in timestamp."""
        return self._data.get('CreateDate')

    @property
    def id(self):  # pylint: disable=invalid-name
        """OU ID."""
        return self._data.get('OrganizationalUnitId')

    @property
    def name(self):
        """The name of the OU."""
        return self._data.get('OrganizationalUnitName')

    @property
    def status(self):
        """The status of the OU."""
        return self._data.get('OrganizationalUnitStatus')

    @property
    def type(self):
        """The type of the OU."""
        return self._data.get('OrganizationalUnitType')

    @property
    def parent_ou_id(self):
        """The id of the parent OU."""
        return self._data.get('ParentOrganizationalUnitId')

    @property
    def parent_ou_name(self):
        """The name of the parent OU."""
        return self._data.get('ParentOrganizationalUnitName')

    def delete(self):
        """Deletes the ou.

        Returns:
            response (bool): True on success, False otherwise.

        """
        return self.control_tower.delete_organizational_unit(self.name)
