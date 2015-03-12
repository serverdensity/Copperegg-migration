# Copperegg migration tool
This migration tool will help you to migrate all your users, tags, probes, devices and most of your alerts. 

### To run the migration tool you need the following. 

* Clone this repo into your harddrive
* Start an account at Server Density
* Get a Server Density [token](https://apidocs.serverdensity.com/#getting-a-token-via-the-ui)
* Get your api key from Copperegg. It's important that the user with this apikey can see all devices. 
* Run `pip install -r requirements.txt`
* Start the migration by running `python migration.py copperegg_api SDtoken`


## Caveats
This migration tool won't be able to migrate the many cloud alerts that copperegg supports since we don't support that yet. 

It won't be able to migrate probe alerts with status code checks for the time being and it won't be able to migrate TCP alert checks. 

## What if the migration fails?
If the migration fail send us an email and tell us why it failed and we'll take a look into it. Our email is hello@serverdensity.com

When you run the migration again it needs to be done from a clean slate so please run `python delete.py SDtoken` before you try the migration tool again. 

## Users
When we add users to Server Density we give them a randomized password, the login name for each user will be their email address. To access the account you simply click the forgotten password to renew your password. 


