"""aws_session_token_updater.py

    Classes:
        AWSSessionTokenUpdater: The main class.
        SessionTokenError(Exception): Custom error for token input issues.
        RetryWarning(Exception): Custom warning for retry catching.
        UserInputError(Exception): Custom error for user input issues.

    Methods:
        retry_on_none_or_empty(decorated_function):

"""
import argparse
import configparser
import functools
import json
import logging
import subprocess
import sys
from os.path import expanduser
from typing import Tuple, Any, Callable, List, Dict, Optional


def retry_on_none_or_empty(
        decorated_function,
) -> Callable[[List[Any], Dict[Any, Any]], Any]:
    """Decorator for providing retries of a function whose output is None or empty.

    Args:
        decorated_function: The function which this decorator was applied to.

    Returns:
        The internal function which actually does the looping.
    """

    @functools.wraps(decorated_function)
    def _retry_on_none_or_empty(*args, **kwargs) -> Any:
        """Wrap the decorated function.

        This function wraps the decorated function and passes any positional and/or keyword
        arguments along to it.

        In order to provide flexibility, the function also checks kwargs for the following:
            retry_count (int):
                The number of times to retry getting the token.
            empty_value_message (str):
                The message to display in the event of a blank input.
            empty_value_log_message (str):
                The message to log in the event of a blank input.

        Args:
            args: Positional arguments for the decorated function.

        Keyword Args:
            kwargs: Keyword arguments for the decorated function.

        Returns:
            (Any): The output from the decorated function.
        """
        retry_count = kwargs.get("retry_count", 3)
        empty_value_message = kwargs.get("empty_value_message", "This input may not be empty.")
        empty_value_log_message = kwargs.get(
            "empty_value_log_message", "The user provided an empty value."
        )
        result: str = ""
        for try_num in range(retry_count, -1, -1):
            result = decorated_function(*args, **kwargs)
            if not result:
                print(empty_value_message, f"{try_num} tries remain.")
                logging.debug(empty_value_log_message)
                if try_num < 1:
                    logging.debug("User ran out of input tries.")
                    raise UserInputError()
                continue
            break
        return result

    return _retry_on_none_or_empty


class RetryWarning(Exception):
    """There was an issue, so we're retrying."""


class SessionTokenError(Exception):
    """There was an error getting an AWS session token."""


class UserInputError(Exception):
    """The user failed to enter valid input in the set number of tries."""


class AWSSessionTokenUpdater:
    """Update the AWS session token for a specified user.

    This class creates or updates a session token for a given user under a given profile in your
    AWS credentials file.  It will also add or update the corresponding profile in your config
    file with the appropriate data.

    """

    # region Private Class Attributes
    _AWS_PROFILE_HEADING_TOKENIZED: str = "profile {profile_name}"
    _MFA_SERIAL_NUMBER_TOKENIZED: str = "arn:aws:iam::{aws_account_id}:mfa/{user_name}"
    _REGION_KEY: str = "region"
    _OUTPUT_KEY: str = "output"
    _AWS_ACCESS_KEY_ID_KEY: str = "aws_access_key_id"
    _AWS_SECRET_ACCESS_KEY_KEY: str = "aws_secret_access_key"
    _AWS_SESSION_TOKEN_KEY: str = "aws_session_token"
    _CMD_ARG_ACCOUNT_ID: str = "--account-id"
    _CMD_ARG_PROFILE_NAME: str = "--profile-name"
    _CMD_ARG_USERNAME: str = "username"
    _CMD_ARG_MFA_TOKEN: str = "mfa-token"

    _CMD_LOCAL_FORMAT_KUBECTL_CREATE_SECRET: str = (
        "kubectl create secret docker-registry {secret_name} --docker-username=AWS "
        "--docker-password={docker_password} --docker-server={aws_account_id}.dkr.ecr."
        "us-east-1.amazonaws.com --dry-run=client -o yaml | kubectl apply -f -"
    )
    # This command structure lets kubectl build the secret yaml for us and just pass it in to
    # apply as file-like input.
    # This is necessary for the case where we're updating an existing secret from the terminal.

    _CMD_REMOTE_FORMAT_KUBECTL_CREATE_SECRET: str = (
        "kubectl create secret docker-registry {secret_name} --docker-username=AWS "
        "--docker-password={docker_password} --docker-server={aws_account_id}.dkr.ecr."
        "us-east-1.amazonaws.com --dry-run=client -o yaml | kubectl apply --kubeconfig "
        "{kubeconfig} -n {namespace} -f -"
    )
    # This command structure lets kubectl build the secret yaml for us and just pass it in to
    # apply as file-like input.
    # This is necessary for the case where we're updating an existing secret from the terminal.

    _CMD_FORMAT_GET_SESSION_TOKEN: str = (
        "aws sts get-session-token --serial-number {_mfa_serial_number} "
        "--token-code {mfa_token} --duration-seconds {token_duration}"
    )
    # This command gets a session token from AWS.

    _CMD_FORMAT_GET_LOGIN_PASSWORD_TOKEN: str = (
        "aws ecr get-login-password --profile {self.profile_name}"
    )

    # This command gets a login password based on the specified AWS security profile.
    # endregion

    # region Context Managers
    def __init__(
            self,
            aws_account_id: Optional[str] = "963234657927",
            profile_name: Optional[str] = "mfa",
            username: Optional[str] = None,
            mfa_token: Optional[str] = None,
    ):
        """Constructs all the necessary attributes for the AWSSessionTokenUpdater object.

        Parameters:
            aws_account_id: The AWS account ID to use for the token request. Default value.
            profile_name: The profile name to enter token details under in the credentials and
            config files.
            username: The username to use for requesting the token.
            mfa_token: The token provided by your MFA device.
        """
        # Initialize our logging
        logging.basicConfig(level=self._cmd_args.log_level.upper())
        logging.debug("Logging initialized.")

        # region User-interactive inputs with defaults or method parameters
        self.aws_account_id: str = aws_account_id
        self.mfa_token: str = mfa_token
        self.profile_name: str = profile_name
        self.username: str = username
        # endregion

        # region Non-interactive inputs with defaults
        self.aws_config_path: str = f"{expanduser('~')}/.aws/config"
        self.aws_credentials_path: str = f"{expanduser('~')}/.aws/credentials"
        self.encoding: str = "utf-8"
        self.local_kubeconfig_path: str = f"{expanduser('~')}/.kube/config"
        self.local_namespace: str = "default"
        self.log_level: str = "info"
        self.output_format: str = "json"
        self.rancher_kubeconfig_path: str = f"{expanduser('~')}/.kube/rancher_kubeconfig.yaml"
        self.rancher_namespace: str = "systemlink-testinsights"
        self.region_name: str = "us-east-1"
        self.secret_name: str = "aws-ecr-secret"
        self.token_duration: str = "129600"
        self._access_key_id: str = ""
        self._cmd_args: argparse.Namespace = argparse.Namespace()
        self._mfa_serial_number: str = ""
        self._secret_access_key: str = ""
        self._session_token: str = ""
        # endregion

        # Process the command arguments for further assignment.
        self._process_arguments()

        # Override the defaults above with anything which might've been provided as
        # command arguments.
        self.aws_account_id: str = self._cmd_args.aws_account_id
        self.aws_config_path: str = self._cmd_args.config_path
        self.aws_credentials_path: str = self._cmd_args.credentials_path
        self.local_kubeconfig_path: str = self._cmd_args.kubeconfig_local
        self.local_namespace: str = self._cmd_args.local_namespace
        self.log_level: str = self._cmd_args.log_level
        self.rancher_kubeconfig_path: str = self._cmd_args.kubeconfig
        self.mfa_token: str = self._cmd_args.mfa_token
        self.output_format: str = self._cmd_args.output_format
        self.profile_name: str = self._cmd_args.profile_name
        self.region_name: str = self._cmd_args.region_name
        self.username: str = self._cmd_args.username

        # This is the serial number for our AWS MFA service
        self._mfa_serial_number: str = self._MFA_SERIAL_NUMBER_TOKENIZED.format(
            aws_account_id=self.aws_account_id, user_name=self.username
        )

    def __enter__(self):
        """Adds support to this class for use in ``with`` statements."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Logs exit values ``exc_type``, ``exc_val`` and ``exc_tb``."""
        if exc_type:
            logging.debug(f"exc_type: {exc_type}")

        if exc_val:
            logging.debug(f"exc_val: {exc_val}")

        if exc_tb:
            logging.debug(f"exc_tb: {exc_tb}")

    # endregion

    # region Private Methods
    # region Initializers
    def _process_arguments(self) -> None:
        """Processes commandline arguments.

        This method processes any recognized command arguments passed in by the user.

        Warning::
             This method uses the initialized instance variables defined in ``__init__()`` as
             argument defaults.  Please ensure that all defaults are initialized prior to calling
             this method.

        Returns:
            None
        """

        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--account-id",
            dest="aws_account_id",
            type=str,
            default=self.aws_account_id,
            help=f"The AWS account id used for the session token request: [{self.aws_account_id}]",
        )
        parser.add_argument(
            "--aws-config-path",
            dest="aws_config_path",
            type=str,
            default=self.aws_config_path,
            help=f"The path to your AWS config file: [{self.aws_config_path}]",
        )
        parser.add_argument(
            "--aws-credentials-path",
            dest="aws_credentials_path",
            type=str,
            default=self.aws_credentials_path,
            help=f"The path to your AWS credentials file: [{self.aws_credentials_path}]",
        )
        parser.add_argument(
            "--local-kubeconfig_path",
            dest="local_kubeconfig_path",
            type=str,
            default=self.local_kubeconfig_path,
            help=f"The path to a local .kube/config YAML file: [{self.local_kubeconfig_path}]",
        )
        parser.add_argument(
            "--local-namespace",
            dest="local_namespace",
            type=str,
            default=self.local_namespace,
            help=f"The name of a local kubernetes namespace to use: [{self.local_namespace}]",
        )
        parser.add_argument(
            "--log-level",
            dest="log_level",
            type=str,
            default=self.log_level,
            help=f"The logging level under which to run the script: [{self.log_level}]",
        )
        parser.add_argument(
            "--mfa-token",
            dest="mfa_token",
            type=str,
            default=self.mfa_token,
            help=f"The MFA token supplied by your authenticator app: [{self.mfa_token}].",
        )
        parser.add_argument(
            "--output-format",
            dest="output_format",
            type=str,
            default=self.output_format,
            help=f"The output format for AWS auth requests: [{self.output_format}]",
        )
        parser.add_argument(
            "--profile-name",
            dest="profile_name",
            type=str,
            default=self.profile_name,
            help=f"The AWS credentials and config file profile name to work with: "
                 f"[{self.profile_name}]",
        )
        parser.add_argument(
            "--rancher-kubeconfig-path",
            dest="rancher_kubeconfig_path",
            type=str,
            default=self.rancher_kubeconfig_path,
            help=f"The path to a rancher kubeconfig YAML file: [{self.rancher_kubeconfig_path}]",
        )
        parser.add_argument(
            "--region-name",
            dest="region_name",
            type=str,
            default=self.region_name,
            help=f"The AWS region where you wish to work: [{self.region_name}]",
        )
        parser.add_argument(
            "--user-name",
            dest="username",
            type=str,
            default=self.username,
            help=f"The username to supply for the token request: [{self.username}]",
        )

        self._cmd_args = parser.parse_args()

    def _get_user_input(
            self,
            aws_account_id: Optional[str] = None,
            profile_name: Optional[str] = None,
            username: Optional[str] = None,
            mfa_token: Optional[str] = None,
    ) -> None:
        """Get input values from the user.

        User input for the given properties will only be requested in cases where the property
        has neither a default value, nor a value supplied on the commandline.

        Properties:
            aws_account_id (Optional[str]): The AWS account ID to use for the token request.
            profile_name (Optional[str]): The profile name to enter token details under in the
            credentials and config files.
            username (str): The username to use for requesting the token.
            mfa_token (str): The token provided by your MFA device.

        Returns:
            None
        """

        # region Local Functions
        @retry_on_none_or_empty
        def _get_aws_account_id() -> str:
            """Get the AWS account id from the user [has default]."""
            return (
                    str(input(f"Enter your AWS account Id [{self.aws_account_id}]: "))
                    or self.aws_account_id
            )

        @retry_on_none_or_empty
        def _get_profile_name() -> str:
            """Get the profile name from the user [has default]."""
            return (
                    str(input(f"Enter the name of the profile to modify [{self.profile_name}]: "))
                    or self.profile_name
            )

        @retry_on_none_or_empty
        def _get_username() -> str:
            """Get the username from the user [has NO default]"""
            return str(input(f"Enter your username: "))

        @retry_on_none_or_empty
        def _get_mfa_token() -> str:
            """Get the MFA token from the user [has NO default]"""
            return str(input(f"Enter your MFA token value: "))

        # endregion

        # Get provided command arguments and intersect them with those we require values for.
        # The difference between
        # the provided arguments and the required ones is the set of args we need to get values for.
        sys_argv = set(sys.argv)
        input_lookup_keys = {
            self._CMD_ARG_USERNAME,
            self._CMD_ARG_MFA_TOKEN,
            self._CMD_ARG_ACCOUNT_ID,
            self._CMD_ARG_PROFILE_NAME,
        }
        user_provided_keys = sys_argv.intersection(input_lookup_keys)
        input_keys_to_process = list(input_lookup_keys.difference(user_provided_keys))

        # Get only the missing, required user input.
        # Note: In order to support this module being imported, not just a script, we also need
        # to filter out any
        # commands passed in to this function by a developer.
        if not aws_account_id:
            if self._CMD_ARG_ACCOUNT_ID in input_keys_to_process:
                self.aws_account_id = _get_aws_account_id([], {})
        else:
            self.aws_account_id = aws_account_id

        if not profile_name:
            if self._CMD_ARG_PROFILE_NAME in input_keys_to_process:
                self.profile_name = _get_profile_name([], {})
        else:
            self.profile_name = profile_name

        if not username:
            if self._CMD_ARG_USERNAME in input_keys_to_process:
                self.username = _get_username([], {})
        else:
            self.username = username

        if not mfa_token:
            if self._CMD_ARG_MFA_TOKEN in input_keys_to_process:
                self.mfa_token = _get_mfa_token([], {})
        else:
            self.mfa_token = _get_mfa_token([], {})

    # endregion

    # region Auth
    def _get_aws_session_token(self, retry_count: int = 3) -> None:
        """Gets an AWS session token object.

        The return object from a call to ``aws sts get_session_token`` contains the pertinent
        data for the ~/.aws/.credentials section, specified by profile name, in the form of a
        tuple ``(aws_secret_access_key, aws_access_key_id, aws_session_token)``.

        For more information:
            See the AWS documentation on `get_session_token`_.

        Args:
            retry_count (int): The number of times to retry getting the token.

        Returns:
            None

        .. _get_session_token:
            https://docs.aws.amazon.com/cli/latest/reference/sts/get-session-token.html
        """

        # Give the user `retry_count` tries to get their token.
        for count in range(retry_count, 0, -1):
            try:
                # Build and run the command to get the session token.
                command = self._build_get_session_token_command()
                stderr, stdout = self.run_shell_command(command)

                # Log any errors and raise for the loop handler.
                if stderr:
                    logging.debug(f"Raising RetryWarning for another go")
                    raise RetryWarning(stderr)

                # All of our data is in stdout.
                if stdout:
                    logging.debug(stdout)
                    session_token_string = stdout
                    session_token_obj = json.loads(session_token_string)

                    # Pull out the AccessKeyId to enter into the credentials file.
                    self._access_key_id = session_token_obj.get("Credentials", {}).get(
                        "AccessKeyId", ""
                    )
                    logging.debug(f"access_key_id: {self._access_key_id}")

                    # Pull out the SecretAccessKey to enter into the credentials file.
                    self._secret_access_key = session_token_obj.get("Credentials", {}).get(
                        "SecretAccessKey", ""
                    )
                    logging.debug(f"secret_access_key: {self._secret_access_key}")

                    # Pull out the SessionToken to enter into the credentials file.
                    self._session_token = session_token_obj.get("Credentials", {}).get(
                        "SessionToken", ""
                    )
                    logging.debug(f"session_token: {self._session_token}")

                    # We're done, so return to caller.
                    return
                # Kick it around for another try.
                continue
            except RetryWarning as retry_warning:
                """Session Token Acquisition Loop Handler

                Use this exception to handle any command issues which only need retries.
                """
                logging.debug(retry_warning)
                self.mfa_token = str(
                    input(f"Invalid token value, please retry. ({count - 1} tries remain): ")
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
    def run_shell_command(cls, command: str = None) -> Tuple[str, str]:
        """Run the provided command string in the shell.

        Args:
            command: The command to run.

        Returns:
            A tuple in the form (stdout, stderr).
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

        # TODO: Check for existing config file. If not existing, then create.

        config_.read(self.aws_config_path)
        section_name = self._AWS_PROFILE_HEADING_TOKENIZED.format(profile_name=self.profile_name)
        if section_name not in config_.sections():
            config_.add_section(section_name)
        config_[section_name][self._REGION_KEY] = self.region_name
        config_[section_name][self._OUTPUT_KEY] = self.output_format
        with open(self.aws_config_path, "w") as config_file:
            config_.write(config_file)

    def _build_credentials_file(self) -> None:
        """Writes data to the AWS credentials file.

        Returns:
            None
        """

        credentials = configparser.ConfigParser()

        # TODO: Check for existing config file. If not existing, then create.
        # TODO: Handle permission errors on creation, write, etc. of the file.

        # NOTE: If the file doesn't exist, .read() will implicitly create it when it calls
        # `with open(...)`.
        credentials.read(self.aws_credentials_path)

        if self.profile_name not in credentials.sections():
            credentials.add_section(self.profile_name)

        credentials[self.profile_name][self._AWS_ACCESS_KEY_ID_KEY] = self._access_key_id
        credentials[self.profile_name][self._AWS_SECRET_ACCESS_KEY_KEY] = self._secret_access_key
        credentials[self.profile_name][self._AWS_SESSION_TOKEN_KEY] = self._session_token
        with open(self.aws_credentials_path, "w") as credentials_file:
            credentials.write(credentials_file)

    def _build_get_session_token_command(self) -> str:
        """Build the ``aws sts get-session-token`` command.

        For more information, see the AWS documentation on `get_session_token`_.

        Returns:
            (str): A formatted string version of the command to run.

        .. _get_session_token:
            https://docs.aws.amazon.com/cli/latest/reference/sts/get-session-token.html
        """
        command = self._CMD_FORMAT_GET_SESSION_TOKEN.format(
            mfa_serial_number=self._mfa_serial_number,
            mfa_token=self.mfa_token,
            token_duration=self.token_duration,
        )
        logging.debug(f"Command to execute: {command}")
        return command

    def _build_secrets(self) -> None:
        """Creates a .dockerconfigjson secret

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
            kubeconfig (str): The kubeconfig file to use [default: ~/.kube/config].
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
    # endregion

    # region Public Methods
    def update_session_token(
            self,
            aws_account_id: str = Optional[str],
            profile_name: str = Optional[str],
            username: str = None,
            mfa_token: str = None,
    ) -> None:
        """Request and apply a new session token.

        This method's main task is to acquire a session token and use it to apply a secret to a
        k8s namespace.
        It does this by doing the following:
            - Get any required values (aws-account_id, profile_name, username, mfa_token) from
            the user.  In order
            of precedence, defaults < formal parameters < args | input.
            - Request a session token from aws sts get-session-token using subprocess.Popen.
            - Build or update the specified profile section under the credentials and config files.
              - This profile contain data which we need in order to push and pull images from our
              AWS ECR server.
            - Call kubectl create secret docker-registry using subprocess.Popen.

        Args:
            aws_account_id (Optional[str]): The AWS account ID to use for the token request.
            profile_name (Optional[str]): The profile name to enter token details under in the
            credentials and config files.
            username (str): The username to use for requesting the token.
            mfa_token (str): The token provided by your MFA device.

        Returns:
            None
        """
        self._process_arguments()

        try:
            self._get_user_input(
                aws_account_id=aws_account_id, profile_name=profile_name, username=username,
                mfa_token=mfa_token
            )
        except UserInputError:
            input("Failed to obtain authorization.  Press any key to terminate.")
            exit(1)

        try:
            self._get_aws_session_token()
        except SessionTokenError:
            input("Failed to obtain authorization.  Press any key to terminate.")
            exit(1)

        self._build_credentials_file()
        self._build_config_file()
        self._build_secrets()

        logging.debug("Script completed.")
        print("Script execution completed.  Token successfully updated.")

    # endregion


def main() -> None:
    """The main starting point.

    Returns:
        None
    """
    aws_session_token_updater = AWSSessionTokenUpdater()
    aws_session_token_updater.update_session_token()


if __name__ == "__main__":
    main()
