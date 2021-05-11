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

    tower.create_organizational_unit('TestOU')
    >>> True

    tower.delete_organizational_unit('TestOU')
    >>> True
