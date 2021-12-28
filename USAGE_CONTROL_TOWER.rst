======================
Usage for ControlTower
======================


To use ControlTower in a project:

.. code-block:: python

    from awsapilib import ControlTower
    tower = ControlTower('arn:aws:iam::ACCOUNTID:role/ValidAdministrativeRole')

    for account in tower.accounts:
        print(account.name)
    >>> root
        Audit
        Log archive

    for account in tower.accounts:
        print(account.guardrail_compliance_status)
    >>> COMPLIANT
        COMPLIANT
        COMPLIANT

    for ou in tower.organizational_units:
        print(ou.name)
    >>> Custom
        Core
        Root

    # Creates an OU under root
    tower.create_organizational_unit('TestOU')
    >>> True

    # Creates an OU under Workload/Production
    # It would raise NonExistentOU exception if the structure does not exist
    tower.create_organizational_unit('TestOU', parent_hierarchy=['Workload','Production'])
    >>> True

    # Creates an OU under Workload/Production
    # It would create the structure if the structure does not exist
    tower.create_organizational_unit('TestOU', parent_hierarchy=['Workload','Production'], force_create=True)
    >>> True

    # Deletes an OU under Root OU
    tower.delete_organizational_unit('TestOU')
    >>> True

    # Deletes an OU under Workload/Production
    tower.delete_organizational_unit('TestOU', parent_hierarchy=['Workload','Production'])
    >>> True


    # Creates account "account-name" under OU "SomeOu" under Root OU
    tower.create_account(account_name='account-name',
                         account_email='root-email@domain.com',
                         organizational_unit='SomeOU')
    >>> True

    # Creates account "account-name" under OU "SomeOu" under Workload/Production
    # It would raise NonExistentOU exception if the structure does not exist
    tower.create_account(account_name='account-name',
                         account_email='root-email@domain.com',
                         organizational_unit='SomeOU',
                         parent_hierarchy=['Workload','Production'])
    >>> True

    # Creates account "account-name" under OU "SomeOu" under Workload/Production
    # It would create the structure if the structure does not exist
    tower.create_account(account_name='account-name',
                         account_email='root-email@domain.com',
                         organizational_unit='SomeOU',
                         parent_hierarchy=['Workload','Production'],
                         force_parent_hierarchy_creation=True)
    >>> True


    # Creates account "account-name" under OU "SomeOu" under Workload/Production
    # It would create the structure if the structure does not exist
    # Uses all possible attributes.
    tower.create_account(account_name='account-name',
                         account_email='root-email@domain.com',
                         organizational_unit='SomeOU',
                         parent_hierarchy=['Workload','Production'],
                         product_name='product-name-for-account',
                         sso_first_name='Bob',
                         sso_last_name='Builder',
                         sso_user_email='bob-builder@construction.com',
                         force_parent_hierarchy_creation=True)
    >>> True
