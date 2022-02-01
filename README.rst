######################################
AWS Session Token Updater
######################################

AWS Session Token Updater is a python utility script for rotating the password in the
aws-ecr-secret locally and on a kubernetes account (rancher in the default case of this
utility) specified by a ``kubeconfig`` file.

Requirements
=====================================
General
-------

You may use the included requirements.txt to ensure that you have all of this module's
required python packages.

.. code-block:: shell

    pip install -r requirements.txt

Python Version
--------------
This script uses `PEP 484`_ type hints.  For this reason, version 3.5+ is required.

.. _PEP 484:  https://www.python.org/dev/peps/pep-0484/

Module Use Cases
=====================================
This module may be utilized in one of two ways: as a script run from the terminal / console; as
an import as part of another python script / project.

Terminal
-------------------------------------
Commandline usage:

.. code-block:: shell

        python -m aws_session_token_updater.py [
            [--account-id <id>][--aws-config-path <path>]
            [--aws-credentials-path <path>][--local-kubeconfig_path <path>]
            [--local-namespace <namespace>][--log-level <info | warning | debug |...>]
            [--mfa-token <token>][--output-format <json | yaml | ...>]
            [--profile-name <name>][--rancher-kubeconfig-path <path>]
            [--region-name <name>][-username <name>]
        ]

Interactive Arguments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The script takes four values which, if not provided via arguments or method call, it will
try to interactively obtain from the user.

* **account-id**: The AWS account id used for the session token request
* **profile-name**: The name of the AWS credentials profile to work with
* **username**: The username to supply for the token request
* **mfa-token**: The MFA token supplied by your authenticator app

Optional Arguments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The following arguments all have their own defaults, but allow the user to override them to customize
their experience.

* **aws-config-path**: The path to your AWS config file: [``--aws-config-path ~/.aws/config``]
* **aws-credentials-path**: The path to your AWS credentials file: [``~/.aws/credentials``]
* **local-kubeconfig_path**: The path to a local .kube/config YAML file: [``~/.kube/config``]
* **local-namespace**: The name of a local kubernetes namespace to use: [``default``]
* **log-level**: The logging level under which to run the script: [``info``]
* **output-format**: The output format for AWS auth requests: [``json``]
* **rancher-kubeconfig-path**: The path to a rancher kubeconfig YAML file: [``~/.kube/rancher_kubeconfig.yaml``]
* **region-name**: The AWS region where you wish to work: [``us-east-1``]

Examples
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Run the script from the terminal in non-interactive mode:

.. code-block:: shell

    python -m aws_session_token_updater.py --log-level info --account-id <aws-account-id>
    --profile-name <profile-name> --user-name <username> --mfa-token <token-code> [--kubeconfig ~/.kube/rancher-kubeconfig.yaml]

Run the script in fully guided mode:

.. code-block:: shell

    python -m aws_session_token_updater.py [--kubeconfig ~/.kube/rancher-kubeconfig.yaml]

Run the script with partial interaction:

.. code-block:: shell

    python -m aws_session_token_updater.py --aws-account-id <aws-account-id> --profile-name
    <profile-name> [--kubeconfig ~/.kube/rancher-kubeconfig.yaml]


Python Class Import
-------------------------------------
This module may be imported into a python project to allow direct access to the
AWSSessionTokenUpdater class.  In fact, this module does just that when run as a script.

The following is an example of using the AWSSessionTokenUpdater class in the simplest manner.  When
calling ``update_session_token``, any properties that you pass will override all other value sources
for that property.  If you call the method with no properties, as in the example, then any of the
interactive arguments which do not have a default value will be requested from the terminal.

.. code-block:: python

    def main():
        aws_session_token_updater = AWSSessionTokenUpdater()
        aws_session_token_updater.update_session_token()
