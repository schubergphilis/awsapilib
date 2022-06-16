#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: controltower.py
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
#  pylint: disable=too-many-lines

"""
Main code for controltower.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import copy
import json
import logging
import time
from functools import wraps
from time import sleep
from typing import Optional

import boto3
import botocore
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import ReadOnlyCredentials

import requests
from boto3_type_annotations.organizations import Client as OrganizationsClient
from boto3_type_annotations.servicecatalog import Client as ServicecatalogClient
from cachetools import TTLCache
from cachetools import cached
from opnieuw import retry

from awsapilib.authentication import Authenticator, LoggerMixin
from .controltowerexceptions import (UnsupportedTarget,
                                     OUCreating,
                                     NoServiceCatalogAccess,
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
from .resources import (LOGGER,
                        LOGGER_BASENAME,
                        ServiceControlPolicy,
                        CoreAccount,
                        ControlTowerAccount,
                        ControlTowerOU,
                        AccountFactory,
                        OrganizationsOU,
                        ResultOU,
                        GuardRail,
                        CREATING_ACCOUNT_ERROR_MESSAGE,
                        OU_HIERARCHY_DEPTH_SUPPORTED,
                        PROVISIONED_PRODUCTS_UNDER_CHANGE_FILTER)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''18-02-2020'''
__copyright__ = '''Copyright 2020, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class ControlTower(LoggerMixin):  # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """Models Control Tower by wrapping around service catalog."""

    api_content_type = 'application/x-amz-json-1.1'
    api_user_agent = 'aws-sdk-js/2.528.0 promise'
    supported_targets = ['ListManagedOrganizationalUnits',
                         'ManageOrganizationalUnit',
                         'DeregisterOrganizationalUnit',
                         'ListManagedAccounts',
                         'DescribeManagedOrganizationalUnit',
                         'ListGuardrailsForTarget',
                         'GetAvailableUpdates',
                         'DescribeCoreService',
                         'GetAccountInfo',
                         'ListEnabledGuardrails',
                         'ListGuardrails',
                         'ListOrganizationalUnitsForParent',
                         'ListDriftDetails',
                         'GetLandingZoneStatus',
                         'SetupLandingZone',
                         'GetHomeRegion',
                         'ListGuardrailViolations',
                         'GetCatastrophicDrift',
                         'GetGuardrailComplianceStatus',
                         'DescribeAccountFactoryConfig',
                         'PerformPreLaunchChecks',
                         'DeleteLandingZone',
                         ]
    core_account_types = ['PRIMARY', 'LOGGING', 'SECURITY']

    def validate_availability(method):  # noqa
        """Validation decorator."""

        @wraps(method)
        def wrap(*args, **kwargs):
            """Inner wrapper decorator."""
            logger = logging.getLogger(f'{LOGGER_BASENAME}.validation_decorator')
            control_tower_instance = args[0]
            logger.debug('Decorating method: %s', method)
            if not control_tower_instance.is_deployed:
                raise ControlTowerNotDeployed
            if control_tower_instance.busy:
                raise ControlTowerBusy
            return method(*args, **kwargs)  # pylint: disable=not-callable

        return wrap

    def __init__(self, arn, settling_time=90, region=None):
        self.aws_authenticator = Authenticator(arn, region=region)
        self.service_catalog: ServicecatalogClient = boto3.client('servicecatalog',
                                                                  **self.aws_authenticator.assumed_role_credentials)
        self.organizations: OrganizationsClient = boto3.client('organizations',
                                                               **self.aws_authenticator.assumed_role_credentials)

        self._region = region
        self._is_deployed = None
        self.host = f'prod.{self.aws_authenticator.region}.blackbeard.aws.a2z.com'
        self._account_factory_ = None
        self.settling_time = settling_time
        self._root_ou = None
        self._core_accounts = None

    @property
    def _account_factory(self):
        """The AccountFactory object."""
        if any([not self.is_deployed,
                self.percentage_complete != 100]):
            return None
        if self._account_factory_ is None:
            self._account_factory_ = self._get_account_factory(self.service_catalog)
        return self._account_factory_

    @property
    def is_deployed(self):
        """The deployment status of control tower."""
        if not self._is_deployed:
            self.logger.debug('Trying to get the deployed status of the landing zone')
            response = self._call('GetLandingZoneStatus')
            if not response.ok:
                self.logger.error('Failed to get the deployed status of the landing zone with response status '
                                  '"%s" and response text "%s"',
                                  response.status_code, response.text)
                raise ServiceCallFailed(response.text)
            not_deployed_states = ('NOT_STARTED', 'DELETE_COMPLETED', 'DELETE_FAILED')
            self._is_deployed = response.json().get('LandingZoneStatus') not in not_deployed_states
        return self._is_deployed

    @property
    def region(self):
        """Region."""
        if not self.is_deployed:
            self._region = self.aws_authenticator.region
            return self._region
        if self._region is None:
            response = self._call('GetHomeRegion')
            if not response.ok:
                raise ServiceCallFailed(response.text)
            self._region = response.json().get('HomeRegion') or self.aws_authenticator.region
        return self._region

    @staticmethod
    def get_available_regions():
        """The regions that control tower can be active in.

        Returns:
            regions (list): A list of strings of the regions that control tower can be active in.

        """
        url = 'https://api.regional-table.region-services.aws.a2z.com/index.json'
        response = requests.get(url)
        if not response.ok:
            LOGGER.error('Failed to retrieve the info')
            return []
        return [entry.get('id', '').split(':')[1]
                for entry in response.json().get('prices')
                if entry.get('id').startswith('controltower')]

    @property
    @validate_availability
    def core_accounts(self):
        """The core accounts of the landing zone.

        Returns:
            core_accounts (list): A list of the primary, logging and security account.

        """
        if self._core_accounts is None:
            core_accounts = []
            for account_type in self.core_account_types:
                payload = {'AccountType': account_type}
                response = self._call('DescribeCoreService', payload)
                if not response.ok:
                    raise ServiceCallFailed(f'Service call failed with payload {payload}')
                core_accounts.append(CoreAccount(self, account_type, response.json()))
            self._core_accounts = core_accounts
        return self._core_accounts

    @property
    @validate_availability
    def root_ou(self):
        """The root ou of control tower.

        Returns:
            root_ou (ControlTowerOU): The root ou object.

        """
        if self._root_ou is None:
            self._root_ou = self.get_organizational_unit_by_name('Root')
        return self._root_ou

    def _call(self, method, data=None):
        data = data if data else {}
        method = self._validate_target(method)

        return self._call_aws_api(endpoint=self.host,
                                  service="AWSBlackbeardService",
                                  sigv4_service_name="controltower",
                                  method=method,
                                  data=data,
                                  amazon_json_version="1.1",
                                  region=self.aws_authenticator.region)

    def _call_iam_admin(self, method, data=None):
        data = data if data else {}
        return self._call_aws_api(endpoint="iamadmin.amazonaws.com",
                                  service="AWSIdentityManagementAdminService",
                                  sigv4_service_name="iamadmin",
                                  method=method,
                                  data=data,
                                  amazon_json_version="1.0",
                                  region="us-east-1")

    def _call_aws_api(self,  # pylint: disable=too-many-arguments
                      endpoint,
                      service,
                      sigv4_service_name,
                      method,
                      data,
                      amazon_json_version,
                      region):
        url = f"https://{endpoint}/"
        data_encoded = json.dumps(data)
        headers = {
            "Host": endpoint,
            'Content-Type': f'application/x-amz-json-{amazon_json_version}',
            'X-Amz-Target': f'{service}.{method}',
        }
        request = AWSRequest(method="POST", url=url, data=data_encoded, headers=headers)
        session = self.aws_authenticator.session_credentials
        creds = ReadOnlyCredentials(session['sessionId'], session['sessionKey'], session['sessionToken'])
        SigV4Auth(creds, sigv4_service_name, region).add_auth(request)
        return requests.request(method="POST", url=url, headers=dict(request.headers), data=data_encoded)

    @property
    def active_artifact_id(self) -> str:
        """Contains the id of the active artifact.

        Returns:
            str with the artifact id or an empty string

        """
        return self._active_artifact.get('Id', '')

    @property
    @cached(cache=TTLCache(maxsize=1, ttl=20))
    def _active_artifact(self):
        artifacts = self.service_catalog.list_provisioning_artifacts(ProductId=self._account_factory.product_id)
        try:
            return next((artifact for artifact in artifacts.get('ProvisioningArtifactDetails', [])
                         if artifact.get('Active')))
        except StopIteration:
            raise NoActiveArtifactRetrieved('Could not retrieve the active artifact from service catalog.')

    @staticmethod
    def _get_account_factory(service_catalog_client):
        filter_ = {'Owner': ['AWS Control Tower']}
        try:
            return AccountFactory(service_catalog_client,
                                  service_catalog_client.search_products(Filters=filter_
                                                                         ).get('ProductViewSummaries', [''])[0])
        except IndexError:
            raise NoServiceCatalogAccess(('Please make sure the role used has access to the "AWS Control Tower Account '
                                          'Factory Portfolio" in Service Catalog under "Groups, roles, and users"'))

    def _validate_target(self, target):
        if target not in self.supported_targets:
            raise UnsupportedTarget(target)
        return target

    def _get_paginated_results(self,
                               *,
                               content_payload,
                               target,
                               object_group=None,
                               object_type=None,
                               next_token_marker='NextToken'):
        payload = copy.deepcopy(content_payload)
        response, next_token = self._get_partial_response(target, payload, next_token_marker)
        if not object_group:
            yield response.json()
        else:
            for data in response.json().get(object_group, []):
                if object_type:
                    yield object_type(self, data)
                else:
                    yield data
        while next_token:
            payload.update({next_token_marker: next_token})
            response, next_token = self._get_partial_response(target, payload, next_token_marker)
            if not object_group:
                yield response.json()
            else:
                for data in response.json().get(object_group, []):
                    if object_type:
                        yield object_type(self, data)
                    else:
                        yield data

    def _get_partial_response(self, target, payload, next_token_marker):
        response = self._call(target, payload)
        if not response.ok:
            self.logger.debug('Failed getting partial response with payload :%s\n', payload)
            self.logger.debug('Response received :%s\n', response.content)
            raise ValueError(response.text)
        next_token = response.json().get(next_token_marker, '')
        return response, next_token

    @property
    def _update_data(self):
        return next(self._get_paginated_results(content_payload={},
                                                target='GetAvailableUpdates'), {})

    @property
    @validate_availability
    def baseline_update_available(self):
        """Baseline update available."""
        return self._update_data.get('BaselineUpdateAvailable')

    @property
    @validate_availability
    def guardrail_update_available(self):
        """Guardrail update available."""
        return self._update_data.get('GuardrailUpdateAvailable')

    @property
    @validate_availability
    def landing_zone_update_available(self):
        """Landing Zone update available."""
        return self._update_data.get('LandingZoneUpdateAvailable')

    @property
    @validate_availability
    def service_landing_zone_version(self):
        """Service landing zone version."""
        return self._update_data.get('ServiceLandingZoneVersion')

    @property
    @validate_availability
    def user_landing_zone_version(self):
        """User landing zone version."""
        return self._update_data.get('UserLandingZoneVersion')

    @property
    @validate_availability
    def landing_zone_version(self):
        """Landing zone version."""
        return self._update_data.get('UserLandingZoneVersion')

    @property
    @validate_availability
    def organizational_units(self):
        """The organizational units under control tower.

        Returns:
            organizational_units (OrganizationalUnit): A list of organizational units objects under control tower's
            control.

        """
        return self._get_paginated_results(content_payload={'MaxResults': 100},
                                           target='ListManagedOrganizationalUnits',
                                           object_type=ControlTowerOU,
                                           object_group='ManagedOrganizationalUnitList',
                                           next_token_marker='NextToken')

    @validate_availability
    def register_organizations_ou(self, name: str, parent_hierarchy=None, force: bool = False) -> bool:
        """Registers an Organizations OU under control tower.

        Args:
            name (str): The name of the Organizations OU to register to Control Tower.
            force (bool): Forces re-registering if the OU is already controlled by Control Tower

        Returns:
            result (bool): True if successful, False otherwise.

        """
        if self.get_organizational_unit_by_name(name, parent_hierarchy) and not force:
            self.logger.info(f'OU "{name}" is already registered with Control Tower.')
            return True
        try:
            org_ou = self.get_organizations_ou_by_name(name, parent_hierarchy)
        except NonExistentOU:
            org_ou = None
        if not org_ou:
            self.logger.error(f'OU "{name}" does not exist under organizations.')
            return False
        return self._register_org_ou_in_control_tower(org_ou)

    def _get_ou_parent_data(self, parent_id):
        try:
            parent_ou = self.organizations.describe_organizational_unit(OrganizationalUnitId=parent_id
                                                                        ).get('OrganizationalUnit')
            parent_data = {f'Parent{entry}': parent_ou[entry] for entry in ('Id', 'Arn', 'Name')}
        except botocore.exceptions.ClientError as msg:
            # The root account does not follow the same naming convention as the other OUs and raises an exception
            # when trying to describe it. We set it manually in that case.
            if '(InvalidInputException)' not in str(msg):
                raise
            parent_data = {f'Parent{entry}': 'Root' for entry in ('Arn', 'Name')}
            parent_data['ParentId'] = parent_id
        return parent_data

    @validate_availability
    def create_organizational_unit(self, name: str, parent_hierarchy=None, force_create=False) -> bool:
        """Creates a Control Tower managed organizational unit.

        Args:
            name (str): The name of the OU to create.
            parent_hierarchy (list): The list of the parent hierarchy path.
            force_create (bool): Forces the creation of the hierarchy if parents are missing.

        Returns:
            result (bool): True if successful, False otherwise.

        Raises:
            InvalidParentHierarchy: If the hierarchy provided is longer that 5 levels.
            NonExistentOU: If there is an OU missing in the hierarchy and force_create is not set.

        """
        if not parent_hierarchy:
            parent_ou_id = self.root_ou.id
            self.logger.debug(f'Trying to create OU :"{name}" under Root OU.')
        else:
            parent_hierarchy = self._validate_hierarchy(parent_hierarchy)
            parent_ou = self._get_final_parent_ou(list(self.organizations_ous),
                                                  parent_hierarchy,
                                                  force_create=force_create)
            parent_ou_id = parent_ou.id
            self.logger.debug(f'Trying to create OU :"{name}" under "{parent_ou.name}" OU.')
        try:
            response = self.organizations.create_organizational_unit(ParentId=parent_ou_id, Name=name)
        except botocore.exceptions.ClientError as err:
            status = err.response["ResponseMetadata"]["HTTPStatusCode"]
            error_code = err.response["Error"]["Code"]
            error_message = err.response["Error"]["Message"]
            if not status == 200:
                self.logger.error('Failed to create OU "%s" under Organizations with error code %s: %s',
                                  name, error_code, error_message)
                return False
        data = self._get_ou_parent_data(parent_ou_id)
        data.update(response.get('OrganizationalUnit', {}))
        org_ou = OrganizationsOU(data)
        self.logger.debug(response)
        self.logger.info(f'Successfully created OU "{org_ou.name}" under Organizations, '
                         f'need to register to Control Tower, this takes some time.')
        return self._register_org_ou_in_control_tower(org_ou)

    def _describe_organizational_unit(self, organizational_unit_id):
        """The details of an organizational unit."""
        payload = {'OrganizationalUnitId': organizational_unit_id}

        self.logger.debug(f'Trying to get details of OU with id "{organizational_unit_id}"')
        response = self._call('DescribeManagedOrganizationalUnit', payload)
        if not response.ok:
            self.logger.error('Failed to get the description of OU with response status '
                              '"%s" and response text "%s"',
                              response.status_code, response.text)
            raise ServiceCallFailed(payload)
        return [ResultOU(data) for data in response.json().get('ChildrenOrganizationalUnits')]

    def _register_org_ou_in_control_tower(self, org_ou):
        self.logger.debug('Registering or re-registering OU under Control Tower')
        payload = {'OrganizationalUnitId': org_ou.id,
                   'OrganizationalUnitName': org_ou.name}
        response = self._call('ManageOrganizationalUnit', payload)
        if not response.ok:
            self.logger.error('Failed to register OU "%s" to Control Tower with response status "%s" '
                              'and response text "%s"',
                              org_ou.name, response.status_code, response.text)
            return False
        # Making sure that eventual consistency is not a problem here,
        # we wait for control tower to be aware of initialising of the process and then we block on it while it runs.
        result = self._describe_organizational_unit(org_ou.parent_ou_id)
        while not any([all([ou.name == org_ou.name,
                            ou.status == 'COMPLETED']) for ou in result]):
            time.sleep(2)
            result = self._describe_organizational_unit(org_ou.parent_ou_id)
            match = next((ou for ou in result if ou.name == org_ou.name), None)
            if match and match.status not in ['IN_PROGRESS', 'COMPLETED']:
                self.logger.error(f'Failed to register OU "{org_ou.name}" with status "{match.status}"')
                return False
        self.logger.info(f'Successfully registered or re-registered OU "{org_ou.name}" under Control Tower')
        return True

    def _is_busy_with_ou_guardrails(self):
        """The status of guardrails application for OUs in control tower."""
        payload = {'OrganizationUnitStatus': 'IN_PROGRESS'}
        self.logger.debug('Trying to get the status of OU guardrails application with payload "%s"', payload)
        response = self._call('ListManagedOrganizationalUnits', payload)
        if not response.ok:
            self.logger.error('Failed to get the status OU guardrails application with response status '
                              '"%s" and response text "%s"',
                              response.status_code, response.text)
            raise ServiceCallFailed(payload)
        return bool(response.json().get('ManagedOrganizationalUnitList'))

    @validate_availability
    def delete_organizational_unit(self, name: str, parent_hierarchy=None) -> bool:
        """Deletes a Control Tower managed organizational unit.

        Args:
            name (str): The name of the OU to delete.
            parent_hierarchy (list): A list of names of the hierarchy for a parent starting with 'Root'

        Returns:
            result (bool): True if successful, False otherwise.

        Raises:
            NonExistentOU: If an OU does not exist in the hierarchy.

        """
        organizational_unit = self.get_organizational_unit_by_name(name, parent_hierarchy)
        if not organizational_unit:
            self.logger.error('No organizational unit with name :"%s" registered with Control Tower', name)
            return False
        payload = {'OrganizationalUnitId': organizational_unit.id}
        self.logger.debug('Trying to unregister OU "%s" with payload "%s"', name, payload)
        response = self._call('DeregisterOrganizationalUnit', payload)
        if not response.ok:
            self.logger.error('Failed to unregister OU "%s" with response status "%s" and response text "%s"',
                              name, response.status_code, response.text)
            return False
        self.logger.debug('Successfully unregistered management of OU "%s" from Control Tower', name)
        self.logger.debug('Trying to delete OU "%s" from Organizations', name)
        response = self.organizations.delete_organizational_unit(OrganizationalUnitId=organizational_unit.id)
        self.logger.debug(response)
        return bool(response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200)

    @staticmethod
    def _validate_hierarchy(hierarchy):
        if not isinstance(hierarchy, (list, tuple)):
            raise InvalidParentHierarchy(f'Only "list" is a valid argument, received "{type(hierarchy)}"')
        if isinstance(hierarchy, tuple):
            hierarchy = list(hierarchy)
        if not hierarchy[0] == 'Root':
            hierarchy.insert(0, 'Root')
        hierarchy = [ou for ou in hierarchy if ou]
        if len(hierarchy) > OU_HIERARCHY_DEPTH_SUPPORTED:
            raise InvalidParentHierarchy(f'Only {OU_HIERARCHY_DEPTH_SUPPORTED} levels are supported under Root OU, '
                                         f'received {hierarchy} that is {len(hierarchy)}')
        return hierarchy

    @staticmethod
    def _get_ou_by_attribute_pairs(ou_container, attribute_pairs):
        return next((ou for ou in ou_container
                     if all([getattr(ou, name) == value for name, value in attribute_pairs.items()])), None)

    def _get_final_parent_ou(self, organizational_units, hierarchy, parent_ou_id=None, force_create=False):
        organizational_unit = None
        parent_ou_name = None
        working_path = []
        for name in hierarchy:
            attributes = {'name': name,
                          'parent_ou_id': parent_ou_id}
            organizational_unit = ControlTower._get_ou_by_attribute_pairs(organizational_units, attributes)
            if all([not organizational_unit, not force_create]):
                raise NonExistentOU(f'No OU with name "{name}" and parent OU name "{parent_ou_name}" '
                                    f'and parent id "{parent_ou_id}"')
            if not organizational_unit:
                self.logger.info(f'Attempting to create missing "{name}" OU.')
                if self.create_organizational_unit(name, parent_hierarchy=working_path, force_create=force_create):
                    organizational_unit = self.get_organizational_unit_by_name(name, parent_hierarchy=working_path)
                else:
                    raise NonExistentOU(f'Unable to create OU "{name}"')
            parent_ou_id = organizational_unit.id
            parent_ou_name = organizational_unit.name
            working_path.append(name)
        return organizational_unit

    def _get_ou_from_container_by_name(self, container, name, parent_hierarchy=None):
        if not parent_hierarchy:
            attributes = {'name': name,
                          'parent_ou_name': None if name == 'Root' else 'Root'}
            return self._get_ou_by_attribute_pairs(container, attributes)
        parent_hierarchy = parent_hierarchy or []
        hierarchy = self._validate_hierarchy(parent_hierarchy)
        organizational_units = list(container)
        parent_ou = self._get_final_parent_ou(organizational_units, hierarchy)
        attributes = {'name': name,
                      'parent_ou_id': parent_ou.id}
        return self._get_ou_by_attribute_pairs(container, attributes)

    @validate_availability
    def get_organizational_unit_by_name(self, name, parent_hierarchy=None):
        """Gets a Control Tower managed Organizational Unit by name.

        Args:
            name (str): The name of the organizational unit to retrieve.
            parent_hierarchy (list): A list of names of the hierarchy for a parent starting with 'Root'

        Returns:
            result (ControlTowerOU): A OU object on success, None otherwise.

        Raises:
            NonExistentOU: If an OU does not exist in the hierarchy.

        """
        return self._get_ou_from_container_by_name(list(self.organizational_units), name, parent_hierarchy)

    @validate_availability
    def get_organizational_unit_by_id(self, id_):
        """Gets a Control Tower managed Organizational Unit by id.

        Args:
            id_ (str): The id of the organizational unit to retrieve.

        Returns:
            result (ControlTowerOU): A OU object on success, None otherwise.

        """
        return next((ou for ou in self.organizational_units if ou.id == id_), None)

    @property
    @validate_availability
    def organizations_ous(self):
        """The organizational units under Organizations.

        Returns:
            organizational_units (OrganizationsOU): A list of organizational units objects under Organizations.

        """
        client = self.organizations
        root_ou = OrganizationsOU({'Id': self.root_ou.id,
                                   'Name': 'Root',
                                   'Arn': 'RootArn',
                                   'ParentId': None,
                                   'ParentArn': None,
                                   'ParentName': None})
        result = [root_ou]

        def get_ou_ids(parent_id):
            paginator = client.get_paginator('list_organizational_units_for_parent')
            iterator = paginator.paginate(ParentId=parent_id)
            for page in iterator:
                for unit in page['OrganizationalUnits']:
                    try:
                        unit.update(self._get_ou_parent_data(parent_id))
                        org_ou = OrganizationsOU(unit)
                        result.append(org_ou)
                        result.extend(get_ou_ids(org_ou.id))
                    except TypeError:
                        continue
        get_ou_ids(self.root_ou.id)
        return result

    @validate_availability
    def get_organizations_ou_by_name(self, name, parent_hierarchy=None):
        """Gets an Organizations managed Organizational Unit by name.

        Args:
            name (str): The name of the organizational unit to retrieve.
            parent_hierarchy (list): A list of names of the hierarchy for a parent starting with 'Root'

        Returns:
            result (OrganizationsOU): A OU object on success, None otherwise.

        """
        return self._get_ou_from_container_by_name(list(self.organizations_ous), name, parent_hierarchy)

    @validate_availability
    def get_organizations_ou_by_id(self, id_):
        """Gets an Organizations managed Organizational Unit by id.

        Args:
            id_ (str): The id of the organizational unit to retrieve.

        Returns:
            result (OrganizationsOU): A OU object on success, None otherwise.

        """
        return next((ou for ou in self.organizations_ous if ou.id == id_), None)

    @validate_availability
    def get_organizations_ou_by_arn(self, arn):
        """Gets an Organizations managed Organizational Unit by arn.

        Args:
            arn (str): The arn of the organizational unit to retrieve.

        Returns:
            result (OrganizationsOU): A OU object on success, None otherwise.

        """
        return next((ou for ou in self.organizations_ous if ou.arn == arn), None)

    @property
    @validate_availability
    def accounts(self):
        """The accounts under control tower.

        Returns:
            accounts (Account): A list of account objects under control tower's control.

        """
        return self._get_paginated_results(content_payload={'MaxResults': 100},
                                           target='ListManagedAccounts',
                                           object_type=ControlTowerAccount,
                                           object_group='ManagedAccountList',
                                           next_token_marker='NextToken')

    @property
    def _service_catalog_accounts_data(self):
        products = self.service_catalog.search_provisioned_products()
        return [data for data in products.get('ProvisionedProducts', [])
                if data.get('Type', '') == 'CONTROL_TOWER_ACCOUNT']

    @validate_availability
    def get_available_accounts(self):
        """Retrieves the available accounts from control tower.

        Returns:
            accounts (Account): A list of available account objects under control tower's control.

        """
        return self._filter_for_status('AVAILABLE')

    @validate_availability
    def get_erroring_accounts(self):
        """Retrieves the erroring accounts from control tower.

        Returns:
            accounts (Account): A list of erroring account objects under control tower's control.

        """
        return self._filter_for_status('ERROR')

    @validate_availability
    def get_accounts_with_available_updates(self):
        """Retrieves the accounts that have available updates from control tower.

        Returns:
            accounts (Account): A list of account objects under control tower's control with available updates.

        """
        return [account for account in self.accounts if account.has_available_update]

    @validate_availability
    def get_updated_accounts(self):
        """Retrieves the accounts that have no available updates from control tower.

        Returns:
            accounts (Account): A list of account objects under control tower's control with no available updates.

        """
        return [account for account in self.accounts if not account.has_available_update]

    def get_changing_accounts(self):
        """Retrieves the under change accounts from control tower.

        Returns:
            accounts (Account): A list of under change account objects under control tower's control.

        """
        changing_products = self.service_catalog.search_provisioned_products(
            Filters={
                "SearchQuery": PROVISIONED_PRODUCTS_UNDER_CHANGE_FILTER
            }
        )

        return [ControlTowerAccount(self, {'AccountId': data.get('PhysicalId')})
                for data in changing_products.get('ProvisionedProducts', [])]

    def _filter_for_status(self, status):
        return [account for account in self.accounts if account.service_catalog_status == status]

    def _get_by_attribute(self, attribute, value):
        return next((account for account in self.accounts
                     if getattr(account, attribute) == value), None)

    def _get_service_catalog_data_by_account_id(self, account_id):
        return next((data for data in self._service_catalog_accounts_data
                     if data.get('PhysicalId') == account_id), None)

    @validate_availability
    def get_account_by_email(self, email):
        """Retrieves an account by email.

        Returns:
            account (Account): An account object that matches the email or None.

        """
        return self._get_by_attribute('email', email)

    @validate_availability
    def get_account_by_name(self, name):
        """Retrieves an account by name.

        Returns:
            account (Account): An account object that matches the name or None.

        """
        return self._get_by_attribute('name', name)

    @validate_availability
    def get_account_by_id(self, id_):
        """Retrieves an account by id.

        Returns:
            account (Account): An account object that matches the id or None.

        """
        return self._get_by_attribute('id', id_)

    @validate_availability
    def get_account_by_arn(self, arn):
        """Retrieves an account by arn.

        Returns:
            account (Account): An account object that matches the arn or None.

        """
        return self._get_by_attribute('arn', arn)

    @retry(retry_on_exceptions=OUCreating, max_calls_total=7, retry_window_after_first_call_in_seconds=60)
    @validate_availability
    def create_account(self,  # pylint: disable=too-many-arguments, too-many-locals
                       account_name: str,
                       account_email: str,
                       organizational_unit: str,
                       parent_hierarchy: list = None,
                       product_name: str = None,
                       sso_first_name: str = None,
                       sso_last_name: str = None,
                       sso_user_email: str = None,
                       force_parent_hierarchy_creation=False) -> bool:
        """Creates a Control Tower managed account.

        Args:
            account_name (str): The name of the account.
            account_email (str): The email of the account.
            organizational_unit (str): The organizational unit that the account should be under.
            parent_hierarchy (list): The hierarchy under where the OU needs to be placed. Defaults to Root.
            product_name (str): The product name, if nothing is provided it uses the account name.
            sso_first_name (str): The first name of the SSO user, defaults to "Control"
            sso_last_name (str): The last name of the SSO user, defaults to "Tower"
            sso_user_email (str): The email of the sso, if nothing is provided it uses the account email.
            force_parent_hierarchy_creation (bool): Forces the creation of missing OUs in the provided hierarchy.

        Returns:
            result (bool): True on success, False otherwise.

        Raises:
            NonExistentOU: If the parent hierarchy provided does not exist and force is not provided as a flag.
            InvalidParentHierarchy: If the parent hierarchy provided is invalid and force is not provided as a flag.
            EmailInUse: If email provided is already used in AWS.

        """
        if self.is_email_used(account_email):
            raise EmailInUse(account_email)
        product_name = product_name or account_name
        sso_user_email = sso_user_email or account_email
        sso_first_name = sso_first_name or 'Control'
        sso_last_name = sso_last_name or 'Tower'
        try:
            ou_details = self.get_organizational_unit_by_name(organizational_unit, parent_hierarchy)
        except NonExistentOU:
            ou_details = None
        if all([not ou_details, not force_parent_hierarchy_creation]):
            message = f'There does not seem to be an OU {organizational_unit} under hierarchy {parent_hierarchy}'
            raise NonExistentOU(message)
        if not ou_details:
            if not self.create_organizational_unit(name=organizational_unit,
                                                   parent_hierarchy=parent_hierarchy,
                                                   force_create=force_parent_hierarchy_creation):
                self.logger.error('Unable to create the organizational unit or hierarchy required!')
                return False
        ou_details = self.get_organizational_unit_by_name(organizational_unit, parent_hierarchy)
        if not ou_details:
            raise NonExistentOU('Unable to create the required OU.')
        organizational_unit = f'{organizational_unit} ({ou_details.id})'
        arguments = {'ProductId': self._account_factory.product_id,
                     'ProvisionedProductName': product_name,
                     'ProvisioningArtifactId': self._active_artifact.get('Id'),
                     'ProvisioningParameters': [{'Key': 'AccountName',
                                                 'Value': account_name},
                                                {'Key': 'AccountEmail',
                                                 'Value': account_email},
                                                {'Key': 'SSOUserFirstName',
                                                 'Value': sso_first_name},
                                                {'Key': 'SSOUserLastName',
                                                 'Value': sso_last_name},
                                                {'Key': 'SSOUserEmail',
                                                 'Value': sso_user_email},
                                                {'Key': 'ManagedOrganizationalUnit',
                                                 'Value': organizational_unit}]}
        try:
            response = self.service_catalog.provision_product(**arguments)
        except botocore.exceptions.ClientError as err:
            if CREATING_ACCOUNT_ERROR_MESSAGE in err.response['Error']['Message']:
                raise OUCreating
            raise
        response_metadata = response.get('ResponseMetadata', {})
        success = response_metadata.get('HTTPStatusCode') == 200
        if not success:
            self.logger.error('Failed to create account, response was :%s', response_metadata)
            return False
        # Making sure that eventual consistency is not a problem here,
        # we wait for control tower to be aware of the service catalog process
        while not self.busy:
            time.sleep(1)
        return True

    @property
    @validate_availability
    def service_control_policies(self):
        """The service control policies under organization.

        Returns:
            service_control_policies (list): A list of SCPs under the organization.

        """
        return [ServiceControlPolicy(data)
                for data in self.organizations.list_policies(Filter='SERVICE_CONTROL_POLICY').get('Policies', [])]

    @validate_availability
    def get_service_control_policy_by_name(self, name):
        """Retrieves a service control policy by name.

        Args:
            name (str): The name of the SCP to retrieve

        Returns:
            scp (ServiceControlPolicy): The scp if a match is found else None.

        """
        return next((scp for scp in self.service_control_policies
                     if scp.name == name), None)

    @validate_availability
    def update(self):
        """Updates the control tower to the next available version.

        Returns:
            bool: True on success, False on failure.

        """
        if not self.landing_zone_update_available:
            self.logger.warning('Landing zone does not seem to need update, is at version %s',
                                self.landing_zone_version)
            return False
        log_account = next((account for account in self.core_accounts if account.label == 'LOGGING'), None)
        if not log_account:
            raise ServiceCallFailed('Could not retrieve logging account to get the email.')
        security_account = next((account for account in self.core_accounts if account.label == 'SECURITY'), None)
        if not security_account:
            raise ServiceCallFailed('Could not retrieve security account to get the email.')
        payload = self._get_update_payload(log_account.email, security_account.email)
        self.logger.debug('Trying to update the landing zone with payload "%s"', payload)
        response = self._call('SetupLandingZone', payload)
        if not response.ok:
            self.logger.error('Failed to update the landing zone with response status "%s" and response text "%s"',
                              response.status_code, response.text)
            return False
        self.logger.debug('Successfully started updating landing zone')
        # Making sure that eventual consistency is not a problem here,
        # we wait for control tower to be aware of the service catalog process
        while not self.busy:
            time.sleep(1)
        return True

    def _get_update_payload(self, log_account_email, security_account_email):
        content = {'HomeRegion': self.region,
                   'LogAccountEmail': log_account_email,
                   'SecurityAccountEmail': security_account_email}
        if self.landing_zone_version == '2.6':
            region_list = [{"Region": region,
                            "RegionConfigurationStatus": "ENABLED" if region in self.governed_regions else "DISABLED"}
                           for region in self.get_available_regions()]
            content.update({'SetupLandingZoneActionType': 'UPDATE',
                            'RegionConfigurationList': region_list})
        return content

    @property
    def busy(self):
        """Busy."""
        return any([self.status == 'IN_PROGRESS',
                    self.status == 'DELETE_IN_PROGRESS',
                    self.get_changing_accounts(),
                    self._is_busy_with_ou_guardrails()])

    @property
    def status(self):
        """Status."""
        return self._get_status().get('LandingZoneStatus')

    @property
    def percentage_complete(self):
        """Percentage complete."""
        return self._get_status().get('PercentageComplete')

    @property
    def deploying_messages(self):
        """Deploying messages."""
        return self._get_status().get('Messages')

    @property
    def region_metadata_list(self):
        """Region metadata list."""
        return self._get_status().get('RegionMetadataList')

    @property
    def governed_regions(self):
        """Governed regions."""
        return [region.get('Region')
                for region in self.region_metadata_list if region.get('RegionStatus') == 'GOVERNED']

    @property
    def not_governed_regions(self):
        """Not governed regions."""
        return [region.get('Region')
                for region in self.region_metadata_list if region.get('RegionStatus') == 'NOT_GOVERNED']

    def _get_status(self):
        self.logger.debug('Trying to get the landing zone status')
        response = self._call('GetLandingZoneStatus')
        if not response.ok:
            self.logger.error('Failed to get the landing zone status with response status "%s" and response text "%s"',
                              response.status_code, response.text)
            return {}
        self.logger.debug('Successfully got landing zone status.')
        return response.json()

    @property
    @validate_availability
    def drift_messages(self):
        """Drift messages."""
        self.logger.debug('Trying to get the drift messages of the landing zone')
        response = self._call('ListDriftDetails')
        if not response.ok:
            self.logger.error('Failed to get the drift message of the landing zone with response status "%s" and '
                              'response text "%s"',
                              response.status_code, response.text)
            return []
        return response.json().get('DriftDetails')

    @property
    @validate_availability
    def enabled_guard_rails(self):
        """Enabled guard rails."""
        output = []
        for result in self._get_paginated_results(content_payload={}, target='ListEnabledGuardrails'):
            output.extend([GuardRail(self, data) for data in result.get('EnabledGuardrailList')])
        return output

    @property
    @validate_availability
    def guard_rails(self):
        """Guard rails."""
        output = []
        for result in self._get_paginated_results(content_payload={}, target='ListGuardrails'):
            output.extend([GuardRail(self, data) for data in result.get('GuardrailList')])
        return output

    @property
    @validate_availability
    def guard_rails_violations(self):
        """List guard rails violations."""
        output = []
        for result in self._get_paginated_results(content_payload={}, target='ListGuardrailViolations'):
            output.extend(result.get('GuardrailViolationList'))
        return output

    @property
    @validate_availability
    def catastrophic_drift(self):
        """List of catastrophic drift."""
        output = []
        for result in self._get_paginated_results(content_payload={}, target='GetCatastrophicDrift'):
            output.extend(result.get('DriftDetails'))
        return output

    def _pre_deploy_check(self):
        """Pre deployment check."""
        self.logger.debug('Trying the pre deployment check')
        response = self._call('PerformPreLaunchChecks')
        if not response.ok:
            self.logger.error('Failed to do the pre deployment checks with response status '
                              '"%s" and response text "%s"',
                              response.status_code, response.text)
            return []
        return response.json().get('PreLaunchChecksResult')

    def is_email_used(self, email):
        """Check email for availability to be used or if it is already in use."""
        self.logger.debug('Trying to check email "%s"', email)
        response = self._call('GetAccountInfo', {'AccountEmail': email})
        if not response.ok:
            self.logger.error('Failed to check for email with response status '
                              '"%s" and response text "%s"',
                              response.status_code, response.text)
            raise EmailCheckFailed(response.text)
        return response.json().get('AccountWithEmailExists')

    def _validate_regions(self, regions):
        available_regions = self.get_available_regions()
        if not set(available_regions).issuperset(set(regions)):
            raise UnavailableRegion(set(regions) - set(available_regions))
        return regions

    def _create_system_role(self, parameters):
        default_params = {'ServicePrincipalName': 'controltower.amazonaws.com',
                          'TemplateVersion': 1}
        default_params.update(parameters)
        self.logger.debug('Trying to system role with parameters "%s"', default_params)
        response = self._call_iam_admin(method='CreateServiceRole', data=default_params)
        try:
            if all([not response.ok,
                    response.status_code == 409,
                    response.json().get('Error', {}).get('Code') == 'EntityAlreadyExists]']):
                self.logger.error('Entity already exists, response status "%s" and response text "%s"',
                                  response.status_code, response.text)
                return True
        except ValueError:
            self.logger.error('Error on request, response status "%s" and response text "%s"',
                              response.status_code, response.text)
            return False
        if not response.ok:
            self.logger.error('Entity already exists, response status "%s" and response text "%s"',
                              response.status_code, response.text)
            return True
        self.logger.debug('Successfully created system role.')
        return True

    def _create_control_tower_admin(self):
        parameters = {'AmazonManagedPolicyArn': 'arn:aws:iam::aws:policy/service-role/AWSControlTowerServiceRolePolicy',
                      'Description': 'AWS Control Tower policy to manage AWS resources',
                      'PolicyName': 'AWSControlTowerAdminPolicy',
                      'RoleName': 'AWSControlTowerAdmin',
                      'TemplateName': 'AWSControlTowerAdmin',
                      'TemplateVersion': 2}
        return self._create_system_role(parameters)

    def _create_control_tower_cloud_trail_role(self):
        parameters = {'Description': 'AWS Cloud Trail assumes this role to create and '
                                     'publish Cloud Trail logs',
                      'PolicyName': 'AWSControlTowerCloudTrailRolePolicy',
                      'RoleName': 'AWSControlTowerCloudTrailRole',
                      'TemplateName': 'AWSControlTowerCloudTrailRole'}
        return self._create_system_role(parameters)

    def _create_control_tower_stack_set_role(self):
        parameters = {'Description': 'AWS CloudFormation assumes this role to deploy '
                                     'stacksets in accounts created by AWS Control Tower',
                      'PolicyName': 'AWSControlTowerStackSetRolePolicy',
                      'RoleName': 'AWSControlTowerStackSetRole',
                      'TemplateName': 'AWSControlTowerStackSetRole'}
        return self._create_system_role(parameters)

    def _create_control_tower_config_aggregator_role(self):
        parameters = {'AmazonManagedPolicyArn': 'arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations',
                      'Description': 'AWS ControlTower needs this role to help in '
                                     'external config rule detection',
                      'RoleName': 'AWSControlTowerConfigAggregatorRoleForOrganizations',
                      'TemplateName': 'AWSControlTowerConfigAggregatorRole'}
        return self._create_system_role(parameters)

    def deploy(self,  # pylint: disable=too-many-arguments,too-many-locals
               logging_account_email: str,
               security_account_email: str,
               logging_account_name: str = 'Log Archive',
               security_account_name: str = 'Audit',
               core_ou_name: str = 'Security',
               custom_ou_name: str = 'Sandbox',
               regions: Optional[list] = None,
               retries: int = 10,
               wait: int = 1) -> bool:
        """Deploys control tower.

        Returns:
            bool: True on success, False on failure.

        """
        if self.is_deployed:
            self.logger.warning('Control tower does not seem to need deploying, already deployed.')
            return True
        regions = self._validate_regions(regions or [self.region])
        region_list = [{"Region": region, "RegionConfigurationStatus": "ENABLED" if region in regions else "DISABLED"}
                       for region in self.get_available_regions()]
        validation = self._pre_deploy_check()
        self.logger.debug('Got validation response %s.', validation)
        if not all([list(entry.values()).pop().get('Result') == 'SUCCESS' for entry in validation]):
            raise PreDeployValidationFailed(validation)
        invalid_emails = [email for email in [logging_account_email, security_account_email]
                          if self.is_email_used(email)]
        if invalid_emails:
            raise EmailInUse(invalid_emails)
        if not all([self._create_control_tower_admin(),
                    self._create_control_tower_cloud_trail_role(),
                    self._create_control_tower_stack_set_role(),
                    self._create_control_tower_config_aggregator_role()]):
            raise RoleCreationFailure('Unable to create required roles AWSControlTowerAdmin, '
                                      'AWSControlTowerCloudTrailRole, AWSControlTowerStackSetRole, '
                                      'AWSControlTowerConfigAggregatorRole, manual cleanup is required.')
        accounts = [{'Accounts': [{'AccountEmail': logging_account_email,
                                   'AccountName': logging_account_name,
                                   'AccountType': 'LOGGING'},
                                  {'AccountEmail': security_account_email,
                                   'AccountName': security_account_name,
                                   'AccountType': 'SECURITY'}],
                     'OrganizationalUnitName': core_ou_name,
                     'OrganizationalUnitType': 'CORE'},
                    {'OrganizationalUnitName': custom_ou_name,
                     'OrganizationalUnitType': 'CUSTOM'}]
        configuration = {'OrganizationStructure': accounts,
                         'RegionConfigurationList': region_list}
        payload = {'Configuration': configuration,
                   'HomeRegion': self.region,
                   'LogAccountEmail': logging_account_email,
                   'SecurityAccountEmail': security_account_email,
                   'RegionConfigurationList': region_list,
                   'SetupLandingZoneActionType': 'CREATE'
                   }

        self.logger.debug('Trying to deploy control tower with payload "%s"', payload)
        return self._deploy(payload, retries, wait)

    def _deploy(self, payload: dict, retries: int = 10, wait: int = 1) -> bool:
        succeeded = False
        while retries:
            response = self._call("SetupLandingZone", payload)
            succeeded = response.ok
            retries -= 1
            if response.ok:
                retries = 0
            if all([not response.ok,
                    retries]):
                self.logger.error('Failed to deploy control tower with response status "%s" and response text "%s"'
                                  'still have %s retries will wait for %s seconds', response.status_code,
                                  response.text, retries, wait)
                sleep(wait)
        if not succeeded:
            self.logger.error('Failed to deploy control tower, retries were spent.. Maybe try again later?')
            return False
        self.logger.debug('Successfully started deploying control tower.')
        # Making sure that eventual consistency is not a problem here,
        # we wait for control tower to be aware of the service catalog process
        while not self.busy:
            time.sleep(1)
        return True

    def decommission(self) -> bool:
        """Decommissions a landing zone.

        The api call does not seem to be enough and although the resources are decommissioned like with
        the proper process, control tower responds with a delete failed on the api, so it seems that
        aws needs to perform actions on their end for the decommissioning to be successful.

        Returns:
            response (bool): True if the process starts successfully, False otherwise.

        """
        response = self._call('DeleteLandingZone')
        if not response.ok:
            self.logger.error('Failed to decommission control tower with response status "%s" and response text "%s"',
                              response.status_code, response.text)
            return False
        self._is_deployed = None
        self.logger.debug('Successfully started decommissioning control tower.')
        return True

    def repair(self):
        """Repairs control tower.

        Returns:
            bool: True on success, False on failure.

        """
        region_list = [{"Region": region, "RegionConfigurationStatus": "ENABLED"}
                       for region in self.governed_regions]
        validation = self._pre_deploy_check()
        self.logger.debug('Got validation response %s.', validation)
        if not all([list(entry.values()).pop().get('Result') == 'SUCCESS' for entry in validation]):
            raise PreDeployValidationFailed(validation)
        if not all([self._create_control_tower_admin(),
                    self._create_control_tower_cloud_trail_role(),
                    self._create_control_tower_stack_set_role(),
                    self._create_control_tower_config_aggregator_role()]):
            raise RoleCreationFailure('Unable to create required roles AWSControlTowerAdmin, '
                                      'AWSControlTowerCloudTrailRole, AWSControlTowerStackSetRole, '
                                      'AWSControlTowerConfigAggregatorRole, manual cleanup is required.')
        log_account = next((account for account in self.core_accounts if account.label == 'LOGGING'), None)
        if not log_account:
            raise ServiceCallFailed('Could not retrieve logging account to get the email.')
        security_account = next((account for account in self.core_accounts if account.label == 'SECURITY'), None)
        if not security_account:
            raise ServiceCallFailed('Could not retrieve security account to get the email.')
        payload = {'HomeRegion': self.region,
                   'LogAccountEmail': log_account.email,
                   'SecurityAccountEmail': security_account.email,
                   'RegionConfigurationList': region_list,
                   'SetupLandingZoneActionType': 'REPAIR'}
        self.logger.debug('Trying to repair control tower with payload "%s"', payload)
        return self._deploy(payload)
