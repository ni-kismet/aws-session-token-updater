import argparse
import configparser
import functools
import json
import logging
import subprocess
import sys
from os.path import expanduser
from typing import Tuple


class SessionTokenError(Exception):
    """There was an error getting an AWS session token."""


class RetryWarning(Exception):
    """There was an issue, so we're retrying."""


class UserInputError(Exception):
    """The user failed to enter valid input in the set number of tries."""


def input_looper(func):
    @functools.wraps(func)
    def wrapper_input_looper(*args, **kwargs) -> str:
        """

        Args:
            *args:
            **kwargs:

        Notes:
            This decorator checks the output for the following:
                retry_count (int): The number of times to retry getting the token.
                empty_value_message (str):
                empty_value_log_message (str):
        Returns:

        """
        retry_count = kwargs.get("retry_count", 3)
        empty_value_message = kwargs.get(
            "empty_value_message", "This input may not be empty."
        )
        empty_value_log_message = kwargs.get(
            "empty_value_log_message", "The user provided an empty value."
        )
        result: str = ""
        for try_num in range(retry_count, 0, -1):
            result = func(*args, **kwargs)
            if not result:
                print(empty_value_message, f"{try_num} tries remain.")
                logging.debug(empty_value_log_message)
                if try_num <= 0:
                    logging.debug("User ran out of input tries.")
                    raise UserInputError()
                continue
            break
        return result

    return wrapper_input_looper


class AWSSessionTokenUpdater:
    """TODO: Docgen"""

    # region Class Attributes
    # This is the AWS region
    _REGION_KEY: str = "region"
    _OUTPUT_KEY: str = "output"
    _PROFILE_CONST: str = "profile "
    _MFA_SERIAL_NUMBER_TOKENIZED: str = "arn:aws:iam::{aws_account_id}:mfa/{user_name}"
    _SECRET_HEADER: str = "{aws_account_id}.dkr.ecr.us-east-1.amazonaws.com"
    _AWS_ACCESS_KEY_ID_KEY: str = "aws_access_key_id"
    _AWS_SECRET_ACCESS_KEY_KEY: str = "aws_secret_access_key"
    _AWS_SESSION_TOKEN_KEY: str = "aws_session_token"
    _CMD_ARG_ACCOUNT_ID: str = "--account-id"
    _CMD_ARG_PROFILE_NAME: str = "--profile-name"
    _CMD_ARG_USERNAME: str = "username"
    _CMD_ARG_MFA_TOKEN: str = "mfa-token"
    # endregion

    # region Command Format Strings
    # This command structure lets kubectl build the secret yaml for us and just pass it in to apply as file-like input.
    # This is necessary for the case where we're updating an existing secret from the terminal.
    _CMD_LOCAL_FORMAT_KUBECTL_CREATE_SECRET: str = (
        "kubectl create secret docker-registry {secret_name} --docker-username=AWS "
        "--docker-password={docker_password} --docker-server={aws_account_id}.dkr.ecr."
        "us-east-1.amazonaws.com --dry-run=client -o yaml | kubectl apply -f -"
    )

    # This command structure lets kubectl build the secret yaml for us and just pass it in to apply as file-like input.
    # This is necessary for the case where we're updating an existing secret from the terminal.
    _CMD_REMOTE_FORMAT_KUBECTL_CREATE_SECRET: str = (
        "kubectl create secret docker-registry {secret_name} --docker-username=AWS "
        "--docker-password={docker_password} --docker-server={aws_account_id}.dkr.ecr."
        "us-east-1.amazonaws.com --dry-run=client -o yaml | kubectl apply --kubeconfig "
        "{kubeconfig} -n {namespace} -f -"
    )

    # This command gets a session token from AWS.
    _CMD_FORMAT_GET_SESSION_TOKEN: str = (
        "aws sts get-session-token --serial-number {mfa_serial_number} "
        "--token-code {mfa_token} --duration-seconds {token_duration}"
    )

    # endregion

    # region Magic Functions
    def __init__(
        self,
        aws_account_id: str = "963234657927",
        profile_name: str = "mfa",
        username: str = "",
        mfa_token: str = "",
    ):
        """TODO: Docgen"""

        # region Command Args: User-interactive inputs with defaults
        self.aws_account_id: str = aws_account_id
        self.profile_name: str = profile_name
        self.username: str = username
        self.mfa_token: str = mfa_token
        # endregion

        # region Command Args: Non-interactive inputs with defaults
        self.access_key_id: str = ""
        self.config_path: str = f"{expanduser('~')}/.aws/config"
        self.credentials_path: str = f"{expanduser('~')}/.aws/credentials"
        self.encoding: str = "utf=8"
        self.local_kubeconfig_path: str = f"{expanduser('~')}/.kube/config"
        self.local_namespace: str = "default"
        self.log_level: str = "info"
        self.mfa_serial_number: str = ""
        self.output_format: str = "json"
        self.rancher_kubeconfig_path: str = (
            f"{expanduser('~')}/.kube/rancher_kubeconfig.yaml"
        )
        self.rancher_namespace: str = "systemlink-testinsights"
        self.region_name: str = "us-east-1"
        self.secret_access_key: str = ""
        self.secret_name: str = "aws-ecr-secret"
        self.session_token: str = ""
        self.token_duration: str = "129600"
        self._cmd_args: argparse.Namespace = argparse.Namespace()
        # endregion

        self._process_arguments()
        self._initialize_variables_and_input()

    def __enter__(self):
        """TODO: Docgen"""

    def __exit__(self, exc_type, exc_val, exc_tb):
        """TODO: Docgen"""

    # endregion

    # region Initializers
    def _process_arguments(self) -> None:
        """Processes commandline arguments."""

        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--account-id",
            dest="account_id",
            type=str,
            default=self.aws_account_id,
            help=f"The id of the account to get a session token for [{self.aws_account_id}].",
        )
        parser.add_argument(
            "--config-path",
            dest="config_path",
            type=str,
            default=self.config_path,
            help=f"The path to your AWS config file [{self.config_path}].",
        )
        parser.add_argument(
            "--credentials-path",
            dest="credentials_path",
            type=str,
            default=self.credentials_path,
            help=f"The path to your AWS credentials file [{self.credentials_path}].",
        )
        parser.add_argument(
            "--kubeconfig",
            dest="kubeconfig",
            type=str,
            default=self.rancher_kubeconfig_path,
            help=f"The path to a Rancher kubeconfig YAML file [{self.rancher_kubeconfig_path}].",
        )
        parser.add_argument(
            "--kubeconfig-local",
            dest="kubeconfig_local",
            type=str,
            default=self.local_kubeconfig_path,
            help=f"The path to a Rancher kubeconfig YAML file [{self.local_kubeconfig_path}].",
        )
        parser.add_argument(
            "--log-level",
            dest="log_level",
            type=str,
            default=self.log_level,
            help=f"The logging level to use [{self.log_level}].",
        )
        parser.add_argument(
            "--output-format",
            dest="output_format",
            type=str,
            default=self.output_format,
            help=f"The output format for AWS auth requests [{self.output_format}].",
        )
        parser.add_argument(
            "--profile-name",
            dest="profile_name",
            type=str,
            default=self.profile_name,
            help=f"The name of the profile section to work with [{self.profile_name}].",
        )
        parser.add_argument(
            "--region-name",
            dest="region_name",
            type=str,
            default=self.region_name,
            help=f"The AWS region where you wish to work [{self.region_name}].",
        )
        parser.add_argument(
            "--user-name",
            dest="username",
            type=str,
            default=self.username,
            help=f"The username to supply for the token request [{self.username}].",
        )
        parser.add_argument(
            "--mfa-token",
            dest="mfa_token",
            type=str,
            default=self.mfa_token,
            help="The MFA token supplied by your authenticator app [''].",
        )

        self._cmd_args = parser.parse_args()

    def _initialize_variables_and_input(self) -> None:
        """Sets the values of the script's globals.

        Returns:
            None
        """
        # Initialize our logging
        logging.basicConfig(level=self._cmd_args.log_level.upper())
        logging.debug("Logging initialized.")

        # Front-load our variables with everything processed from the command args
        self.aws_account_id = self._cmd_args.account_id
        self.config_path = self._cmd_args.config_path
        self.credentials_path = self._cmd_args.credentials_path
        self.local_kubeconfig_path = self._cmd_args.kubeconfig_local
        self.rancher_kubeconfig_path = self._cmd_args.kubeconfig
        self.log_level = self._cmd_args.log_level
        self.mfa_token = self._cmd_args.mfa_token
        self.output_format = self._cmd_args.output_format
        self.profile_name = self._cmd_args.profile_name
        self.region_name = self._cmd_args.region_name
        self.username = self._cmd_args.username

        # This is the serial number for our AWS MFA service
        mfa_serial_number = self._MFA_SERIAL_NUMBER_TOKENIZED.format(
            aws_account_id=self.aws_account_id, user_name=self.username
        )
        logging.debug(f"MFA Serial Number: {mfa_serial_number}")

        # Get any necessary user inputs to store to globals.
        self._get_user_input()

    def _get_user_input(self) -> None:
        """Get input values from the user.

        Returns:
            None
        """

        # region Local Functions
        @input_looper
        def get_aws_account_id() -> str:
            """"""
            return (
                str(input(f"Enter your AWS account Id [{self.aws_account_id}]: "))
                or self.aws_account_id
            )

        @input_looper
        def get_profile_name() -> str:
            """"""
            return (
                str(
                    input(
                        f"Enter the name of the profile to modify [{self.profile_name}]: "
                    )
                )
                or self.profile_name
            )

        @input_looper
        def get_username() -> str:
            """"""
            return str(input(f"Enter your username: "))

        @input_looper
        def get_mfa_token() -> str:
            """"""
            return str(input(f"Enter your MFA token value: "))

        # endregion

        sys_argv = set(sys.argv)
        input_lookup_keys = {
            self._CMD_ARG_USERNAME,
            self._CMD_ARG_MFA_TOKEN,
            self._CMD_ARG_ACCOUNT_ID,
            self._CMD_ARG_PROFILE_NAME,
        }
        user_provided_keys = sys_argv.intersection(input_lookup_keys)
        input_keys_to_process = list(input_lookup_keys.difference(user_provided_keys))

        if self._CMD_ARG_ACCOUNT_ID in input_keys_to_process:
            self.aws_account_id = get_aws_account_id()

        self.profile_name = get_profile_name()
        self.username = get_username()
        self.mfa_token = get_mfa_token()

    # endregion

    # region Auth
    def _get_auth(self, retry_count: int = 3):  # -> Tuple[str, str, str]
        """Gets the AWS session token object based on your username and MFA token.

        Args:
            retry_count (int): The number of times to retry getting the token.

        Returns:
            Output (Tuple[str, str, str]): Returns the pertinent data
                for the ~/.aws/.credentials section specified by profile name in the
                form of a tuple(aws_secret_access_key, aws_access_key_id, aws_session_token).
        """

        # Give the user `retry_count` tries to get their token.
        for count in range(retry_count, 0, -1):
            try:
                # Build and run the command to get the session token.
                command = self._build_get_session_token_command()
                stderr, stdout = self._run_shell_command(command)

                # Log any errors and raise for the loop handler.
                if stderr:
                    logging.warning(f"Raising RetryWarning for another go")
                    raise RetryWarning(stderr)

                # All of our data is in stdout.
                if stdout:
                    logging.debug(stdout)
                    session_token_string = stdout
                    session_token_obj = json.loads(session_token_string)

                    # Pull out the AccessKeyId to enter into the credentials file.
                    self.access_key_id = session_token_obj.get("Credentials", {}).get(
                        "AccessKeyId", ""
                    )
                    logging.debug(f"access_key_id: {self.access_key_id}")

                    # Pull out the SecretAccessKey to enter into the credentials file.
                    self.secret_access_key = session_token_obj.get(
                        "Credentials", {}
                    ).get("SecretAccessKey", "")
                    logging.debug(f"secret_access_key: {self.secret_access_key}")

                    # Pull out the SessionToken to enter into the credentials file.
                    self.session_token = session_token_obj.get("Credentials", {}).get(
                        "SessionToken", ""
                    )
                    logging.debug(f"session_token: {self.session_token}")

                    # We're done, so return to caller.
                    return
                # Kick it around for another try.
                continue
            except RetryWarning as retry_warning:
                """Session Token Acquisition Loop Handler

                Use this exception to handle any command issues which only need retries.
                """
                logging.warning(retry_warning)
                self.mfa_token = str(
                    input(f"Enter your MFA token value ({count - 1} tries remain): ")
                )
            except Exception as ex:
                """Session Token Acquisition Loop Catch-all

                Use this exception to handle any command issues which require loop termination.
                """
                logging.exception(ex)
                raise

        raise SessionTokenError()

    # endregion

    # region Shell Commands
    @classmethod
    def _run_shell_command(cls, command) -> Tuple[str, str]:
        """Run the command in the shell.

        Args:
            command (str): The command to run.

        Returns:
            (Tuple[str, str]): A tuple containing stdout and stderr.
        """
        subprocess_ = subprocess.Popen(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stderr = subprocess_.stderr.read().strip().decode("utf-8")
        stdout = subprocess_.stdout.read().strip().decode("utf-8")
        return stderr, stdout

    # endregion

    # region Builders
    def _build_config_file(self) -> None:
        """Writes data to the AWS config file.

        Returns:
            None
        """

        config_ = configparser.ConfigParser()
        config_.read(self.config_path)
        section_name = f"{self._PROFILE_CONST}{self.profile_name}"
        if section_name not in config_.sections():
            config_.add_section(section_name)
        config_[section_name][self._REGION_KEY] = self.region_name
        config_[section_name][self._OUTPUT_KEY] = self.output_format
        with open(self.config_path, "w") as config_file:
            config_.write(config_file)

    def _build_credentials_file(self) -> None:
        """Writes data to the AWS credentials file.

        Returns:
            None
        """

        credentials = configparser.ConfigParser()

        # If the file doesn't exist, .read() will create it.
        credentials.read(self.credentials_path)

        if self.profile_name not in credentials.sections():
            credentials.add_section(self.profile_name)

        credentials[self.profile_name][self._AWS_ACCESS_KEY_ID_KEY] = self.access_key_id
        credentials[self.profile_name][
            self._AWS_SECRET_ACCESS_KEY_KEY
        ] = self.secret_access_key
        credentials[self.profile_name][self._AWS_SESSION_TOKEN_KEY] = self.session_token
        with open(self.credentials_path, "w") as credentials_file:
            credentials.write(credentials_file)

    def _build_get_session_token_command(self) -> str:
        """Build the command to execute.

        Returns:
            (str): A formatted string version of the command to run.
        """

        command = self._CMD_FORMAT_GET_SESSION_TOKEN.format(
            mfa_serial_number=self._MFA_SERIAL_NUMBER_TOKENIZED.format(
                aws_account_id=self.aws_account_id, user_name=self.username
            ),
            mfa_token=self.mfa_token,
            token_duration=self.token_duration,
        )
        logging.debug(f"Command to execute: {command}")
        return command

    def _build_secrets(self) -> None:
        """Creates a .dockerconfigjson secret with either the local .kube/config or the provided one.

        Returns:
            None
        """
        # Get the login password for the mfa profile we wrote before.
        subprocess_ = subprocess.Popen(
            f"aws ecr get-login-password --profile {self.profile_name}",
            shell=True,
            stdout=subprocess.PIPE,
        )
        encoded_pass = subprocess_.stdout.read().decode(self.encoding).strip()

        if "--kubeconfig" not in sys.argv:
            # Build the local secret.
            self._build_secret(
                kubeconfig=self.local_kubeconfig_path,
                namespace=self.local_namespace,
                encoded_pass=encoded_pass,
            )
        else:
            # Build the rancher secret.
            self._build_secret(
                kubeconfig=self.rancher_kubeconfig_path,
                namespace=self.rancher_namespace,
                encoded_pass=encoded_pass,
            )

    def _build_secret(
        self, kubeconfig: str = None, namespace: str = None, encoded_pass: str = None
    ) -> None:
        """Builds a .dockerconfigjson secret.

        Args:
            kubeconfig (str): The kubeconfig file to use (defaults to ~/.kube/config).
            namespace (str): The namespace in which to install the secret.
            encoded_pass (str): The base64 password to apply.

        Returns:
            None
        """

        create_secret_command = self._CMD_REMOTE_FORMAT_KUBECTL_CREATE_SECRET.format(
            secret_name=self.secret_name,
            docker_password=encoded_pass,
            aws_account_id=self.aws_account_id,
            kubeconfig=kubeconfig,
            namespace=namespace,
        )
        subprocess_ = subprocess.Popen(
            create_secret_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        output = subprocess_.stdout.read().decode(self.encoding).strip()
        logging.debug(output)

    # endregion

    # region Runner
    def update_session_token(
        self,
        account_id: str = "",
        profile_name: str = "",
        username: str = "",
        mfa_token: str = "",
    ) -> None:
        """

        Args:
            account_id (str):
            profile_name (str):
            username (str):
            mfa_token (str):

        Returns:
            None:
        """
        # TODO: Get this part, previously from main(), working
        # _process_arguments()
        #
        # try:
        #     _initialize_variables_and_input()
        # except UserInputError:
        #     input("Failed to obtain authorization.  Press any key to terminate.")
        #
        # try:
        #     _get_auth()
        # except SessionTokenError:
        #     input("Failed to obtain authorization.  Press any key to terminate.")
        #
        # _build_credentials_file()
        # _build_config_file()
        # _build_secrets()

    # endregion


def main() -> None:
    """The main starting point.

    Returns:
        None
    """
    aws_session_token_updater = AWSSessionTokenUpdater()
    aws_session_token_updater.update_session_token()

    # _process_arguments()
    #
    # try:
    #     _initialize_variables_and_input()
    # except UserInputError:
    #     input("Failed to obtain authorization.  Press any key to terminate.")
    #
    # try:
    #     _get_auth()
    # except SessionTokenError:
    #     input("Failed to obtain authorization.  Press any key to terminate.")
    #
    # _build_credentials_file()
    # _build_config_file()
    # _build_secrets()


if __name__ == "__main__":
    main()
