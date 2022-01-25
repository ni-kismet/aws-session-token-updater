# aws_session_token_updater
A python utility script for rotating the password in the aws-ecr-secret locally and on Rancher (if you supply a rancher config.yaml).

## Script Inputs
The script takes 4 possible inputs from the user.  In no given order, they are:
1) _account-id_: The id of the account to get a session token for.
2) _profile-name_: The name of the profile section to work with.
3) _user-name_: The username to supply for the token request.
4) _mfa-token_: The MFA token supplied by your authenticator app.

These inputs may be provided from the commandline in order to run in non-interactive mode.  If any of these inputs are not provided, the script will prompt the user for them.

## Commandline Arguments
The script supports the following commandline arguments:
1) _--account-id_: The id of the account to get a session token for
2) _--profile-name_: The name of the profile section to work with
3) _--user-name_: The username to supply for the token request
4) _--mfa-token_: The MFA token supplied by your authenticator app
5) _--config-path_: The path to your AWS config file [`{home}/.aws/config`]
6) _--credentials-path_: The path to your AWS credentials file [`{home}/.aws/credentials`]
7) _--kubeconfig_: The path to a kubeconfig YAML file [`{home}/.kube/config`]
8) _--log-level_: The logging level to use [`info`]
9) _--output-format_: The output format for AWS auth requests [`json`]
10) _--region-name_: The AWS region where you wish to work [`us-east-1`]

## Script execution
You may run this script in multiple ways...
* Run with no options for guided mode.  The script will prompt you for any necessary values, then create the local secret.  Note that this mode will only ask for critical inputs not passed in as arguments.
  <br>`python -m aws_session_token_rotator`
* Supply the --kubeconfig flag in order to update the secret on rancher.
  <br>`python -m aws_session_token_rotator --kubeconfig ~/.kube/rancher_kubeconfig.yaml -n systemlink-testinsights`
* Supply all required user inputs for non-interactive mode.
  <br>`python -m aws_session_token_rotator --log-level info --account-id {aws_account_id} --profile-name {profile_name} --user-name {user_name} --kubeconfig ~/.kube/rancher_kubeconfig.yaml --mfa-token <mfa_token>`
* To see all available command arguments, run the following:
  <br>`python -m aws_session_token_rotator --help`

