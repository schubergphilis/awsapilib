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
