=========================
Usage for Account Manager
=========================


To use Account Manager in a project:

.. code-block:: python

    from awsapilib import AccountManager, PasswordManager

    password_manager = PasswordManager()
    # Most actions require a captcha to be solved to continue.
    # The process is interactive and you get a prompt to solve the captcha by following a url with it
    # in a standard console or by presenting the captcha in the terminal if you are using iTerm

    # Using the Captcha2 solver would automate the process.
    from awsapilib.captcha import Captcha2
    solver = Captcha2('API_TOKEN_HERE_FOR_2CAPTCHA_SERVICE')
    password_manager = PasswordManager(solver=solver)

    # Request the reset of a password for an account
    password_manager.request_password_reset('EMAIL_OF_AN_ACCOUNT')
    # The above should trigger a reset email with a reset link

    # Reset the password
    password_manager.reset_password('RESET_URL_RECEIVED_BY_EMAIL_HERE', 'PASSWORD_TO_SET')

    account_manager = AccountManager(email, password, region, mfa_serial)
    # Most actions require a captcha to be solved to continue.
    # The process is interactive and you get a prompt to solve the captcha by following a url with it
    # in a standard console or by presenting the captcha in the terminal if you are using iTerm

    # Using the Captcha2 solver would automate the process.
    from awsapilib.captcha import Captcha2
    solver = Captcha2('API_TOKEN_HERE_FOR_2CAPTCHA_SERVICE')
    account_manager = AccountManager(email, password, region, mfa_serial, solver=solver)

    # Enable IAM billing console access for the account
    print(account_manager.iam.billing_console_access)
    >>> False

    account_manager.iam.billing_console_access = True
    print(account_manager.iam.billing_console_access)
    >>> True

    # Interface with MFA actions
    # Create a virtual MFA
    # Warning! Setting an MFA will require re instantiation of the account manager with the new seed
    # before more actions can be performed on the account.
    # Also due to eventual consistency there might be some time required between setting the MFA and
    # being able to use it in which case there might be authentication errors in between if actions are
    # performed in sequence. The time is usually less that half a minute.
    seed = account_manager.mfa.create_virtual_device() # default name is "root-account-mfa-device"
                                                       # can be overridden by passing a name variable
    # !! Save the seed somewhere super safe

    # Get the current virtual MFA
    device = account_manager.mfa.get_virtual_device()
    print(device.serial_number)
    arn:aws:iam::ACCOUNTID:mfa/root-account-mfa-device

    # Delete a virtual MFA
    account_manager.mfa.delete_virtual_mfa(device.serial_number)


    # Update info and terminate account

    # Update name of account
    account_manager.update_account_name('NEW_NAME_TO_SET')

    # Update email of the account
    # Due to eventual consistency there might be some time required between changing the email and
    # being able to use it in which case there might be authentication errors in between if actions are
    # performed in sequence. The time is usually less that half a minute.
    account_manager.update_account_email('NEW_EMAIL_TO_SET')

    # Terminate an account
    account_manager.terminate_account()
