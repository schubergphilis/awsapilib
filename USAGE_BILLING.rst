=================
Usage for Billing
=================


To use Billing in a project:

.. code-block:: python

    from awsapilib import Billing
    billing = Billing('arn:aws:iam::ACCOUNTID:role/ValidAdministrativeRole')

    # Set tax inheritance on
    billing.tax.inheritance = True

    # Set tax information
    billing.tax.set_information('some address', 'some city', 'some postal code', 'legal name', 'VAT', 'country code')

    # Enable pdf invoice
    billing.preferences.pdf_invoice_by_mail = True

    # Enable credit sharing
    billing.preferences.credit_sharing = True

    # Set currency to EUR
    billing.currency = 'EUR'

    # Disable IAM access to billing (needs to be enabled by root and cannot be enabled by this after disabled!)
    billing.iam_access = False
