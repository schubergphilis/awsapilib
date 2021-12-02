=========================
Usage for Account Manager
=========================


To use Account Manager in a project:

.. code-block:: python

    from awsapilib import AccountManager

    account_manager = AccountManager()
    # Most actions require a captcha to be solved to continue.
    # The process is interactive and you get a prompt to solve the captcha by following a url with it
    # in a standard console or by presenting the captcha in the terminal if you are using iTerm

    # Using the Captcha2 solver would automate the process.
    from awsapilib.captcha import Captcha2
    solver = Captcha2('API_TOKEN_HERE_FOR_2CAPTCHA_SERVICE')
    account_manager = AccountManager(solver=solver)

    # Request the reset of a password for an account
    account_manager.request_password_reset(EMAIL_OF_AN_ACCOUNT)
    # The above should trigger a reset email with a reset link

    # Reset the password
    account_manager.reset_password('RESET_URL_RECEIVED_BY_EMAIL_HERE', 'PASSWORD_TO_SET')

    # Terminate an account
    account_manager.terminate_account('EMAIL_OF_THE_ACCOUNT',
                                      'PASSWORD_OF_THE_ACCOUNT',
                                      'REGION_OF_CONSOLE',
                                      'ORIGINAL_MFA_SEED_IF_SET')

    ## Working with MFA virtual tokens in an account
    mfa_manager = account_manager.get_mfa_manager('EMAIL_OF_THE_ACCOUNT',
                                                  'PASSWORD_OF_THE_ACCOUNT',
                                                  'REGION_OF_CONSOLE',
                                                  'ORIGINAL_MFA_SEED_IF_SET')

    # Create mfa if not set
    seed_provided = mfa_manager.create_virtual_mfa('test')
    # Save the seed in a very safe place.

    # Get the device
    device = mfa_manager.get_virtual_mfa_device()
    print(device.serial_number)
    >>> 'arn:aws:iam::ACCOUNTID:mfa/test'

    # Delete the virtual MFA
    mfa_manager.delete_virtual_mfa('arn:aws:iam::ACCOUNTID:mfa/test')
