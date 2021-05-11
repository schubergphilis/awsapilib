=============
Usage for Sso
=============


To use Sso in a project:

.. code-block:: python

    from awsapilib import Sso
    sso = Sso('arn:aws:iam::ACCOUNTID:role/ValidAdministrativeRole')

    for group in sso.groups:
         print(group.name)
