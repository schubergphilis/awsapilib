.. :changelog:

History
-------

0.0.1 (26-04-2021)
---------------------

* First code creation


0.1.0 (11-05-2021)
------------------

* Initial release


0.1.1 (17-05-2021)
------------------

* Filtering out failed accounts from checking their update status


0.1.2 (17-05-2021)
------------------

* Fixed a timing issue with getting the active service catalog product on account creation.


0.2.0 (18-05-2021)
------------------

* Exposed governed and non governed regions and a small fix with latest update changes.


0.2.1 (18-05-2021)
------------------

* Dynamically retrieving updatable information about control tower.


0.2.2 (19-05-2021)
------------------

* Added some blocking on actions to prevent race conditions.


0.2.3 (08-06-2021)
------------------

* Bumped dependencies.


0.2.4 (16-06-2021)
------------------

* Added new feature to provision instance_id for an account


0.3.0 (16-06-2021)
------------------

* Added new method to provision saml config in the account


0.4.0 (17-06-2021)
------------------

* Added provision_saml_provider to the public api


0.4.1 (19-08-2021)
------------------

* Add explict error handling on bad response.


0.4.2 (01-09-2021)
------------------

* Added pagination on organizational OU retrieval.


0.5.0 (09-09-2021)
------------------

* Explicitly passing region to control tower instantiation.


0.5.1 (09-09-2021)
------------------

* Raising exception if csrf token retrieved has no value.


0.5.2 (09-09-2021)
------------------

* Fixed hardcoded url pointing to eu-west-1 making it possible to deploy to other home regions than Ireland.


0.6.0 (01-10-2021)
------------------

* Implemented contol tower repair and bumped dependencies.


0.7.0 (14-10-2021)
------------------

* - Adding a force option to the register_ou function to force re-registering


0.8.0 (14-10-2021)
------------------

* - Adding a force option to the register_ou function to force re-registering


0.9.0 (18-10-2021)
------------------

* - Adding support to also show updated state when the landingzone gets a new configuration


0.10.0 (29-11-2021)
-------------------

* Implemented cloudformation stack set organizations trusted access enabling and disabling.


0.10.1 (29-11-2021)
-------------------

* Added missing dependencies.


1.0.0 (03-12-2021)
------------------

* Implemented account lifecycle and info update, MFA support and IAM billing console enablement.


1.1.0 (18-12-2021)
------------------

* Added support for nested OUs


2.0.0 (28-12-2021)
------------------

* Releasing support for 5 levels of nested OUs


2.0.1 (29-12-2021)
------------------

* Fixed a bug where on account creation the OU was not created unless there was a failure with the parent hierarchy.


2.0.2 (29-12-2021)
------------------

* Fixed a bug with the handling of the OU without hierarchies.


2.1.0 (30-12-2021)
------------------

* Implemented capability of retrieving account by email.


2.1.1 (22-02-2022)
------------------

* Updated 'get_changing_accounts' to use the search_provisioned_products with a filter which will fix the bug where only the first 100 provisioned products were checked for status "UNDER_CHAGE".


2.2.0 (26-04-2022)
------------------

* Fix for new console authentication flow courtesy of Soenke Ruempler <soenke+github@ruempler.eu>, author of the awesome superwerker!


2.3.0 (05-05-2022)
------------------

* Fix for IAM authentication flow.


2.3.1 (18-05-2022)
------------------

* Fix for cases where captcha is actually not required.


2.3.2 (23-05-2022)
------------------

* Another captcha fix for the root console curtesy of Rafael Zamana Kineippe <rafael@zamana.com.br>


3.0.0 (13-06-2022)
------------------

* awsapilib calling aws native apis rather than shadow apis


3.1.0 (17-06-2022)
------------------

* fix control tower deploy/setup 
