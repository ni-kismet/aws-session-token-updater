"""aws_session_token_updater.py

    Classes:
        AWSSessionTokenUpdater: The main class.
        RetryWarning: Custom warning for retry catching.
        SessionTokenError: Custom error for token input issues.
        UserInputError: Custom error for user input issues.

    Decorators:
        retry_on_none_or_empty: Decorator for retrying a function/method *n* times.

"""
import argparse
import configparser
import functools
import json
import logging
import subprocess
import sys
from os.path import expanduser
from typing import Tuple, Any, Callable, Optional, Set, Mapping

import yaml


def retry_on_none_or_empty(decorated_function) -> Callable:
    """Decorator for providing retries of a function whose output is None or empty.

    Args:
        decorated_function: The function which this decorator was applied to.

    Returns:
        The internal function which actually does the looping.
    """

    @functools.wraps(decorated_function)
    def _retry_on_none_or_empty(*args: Set, **kwargs: Mapping) -> Any:
        """Wrap the decorated function.

        This function wraps the decorated function and passes any positional and/or keyword
        arguments along to it.

        In order to provide flexibility, the function also checks kwargs for the following:
            retry_count:
                The number of times to retry getting the token.
            empty_value_message:
                The message to display in the event of a blank input.
            empty_value_log_message:
                The message to log in the event of a blank input.

        Args:
            *args: Positional arguments for the decorated function.

        Keyword Args:
            **kwargs: Keyword arguments for the decorated function.

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


class InvalidConfigError(Exception):
    """The provided config yaml appears to be invalid."""


class MissingConfigError(Exception):
    """Unable to find the default (./config.yaml) or specified config YAML file."""


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
    file with the appropriate default data.

    Methods:
        update_session_token: Request and apply a new session token.
    """

    # region Context Managers
    def __init__(
            self,
            script_config_path: Optional[str] = "config.yaml",
            aws_account_id: Optional[str] = None,
            profile_name: Optional[str] = None,
            username: Optional[str] = None,
            mfa_token: Optional[str] = None,
    ):
        """Constructs all the necessary attributes for the AWSSessionTokenUpdater object.

        Parameters:
            script_config_path: An optional path to the config.yaml to use for configuring the
            scripts constants and defaults.
            aws_account_id: The AWS account ID to use for the token request. Default value.
            profile_name: The profile name to enter token details under in the credentials and
            config files.
            username: The username to use for requesting the token.
            mfa_token: The token provided by your MFA device.
        """

        # Read in the specified config yaml and extract pertinent objects
        self._script_config = self._load_script_config(script_config_path=script_config_path)

        # region Pull the attribute defaults section from the config
        self._session_token_constants = self._script_config.get("sessionTokenConstants", {})
        if not self._session_token_constants:
            raise InvalidConfigError()

        self._attribute_defaults = self._script_config.get("attributeDefaults", {})
        if not self._attribute_defaults:
            raise InvalidConfigError()

        self._argument_parse_constants = self._script_config.get("argumentParseConstants", {})
        if not self._argument_parse_constants:
            raise InvalidConfigError()

        self._user_input_prompts = self._script_config.get("userInputPrompts", {})
        if not self._user_input_prompts:
            raise InvalidConfigError()

        self._shell_commands = self._script_config.get("shellCommands", {})
        if not self._shell_commands:
            raise InvalidConfigError()
        # endregion

        # region Read in the session token constants
        self._aws_access_key_id_key: str = self._session_token_constants.get(
            "awsAccessKeyIdKey", ""
        )
        self._aws_secret_access_key_key: str = self._session_token_constants.get(
            "awsSecretAccessKeyKey", ""
        )
        self._aws_session_token_key: str = self._session_token_constants.get(
            "awsSessionTokenKey", ""
        )
        self._profile_heading_tokenized: str = self._session_token_constants.get(
            "awsProfileHeadingTokenized", ""
        )
        self._output_key: str = self._session_token_constants.get("outputKey", "")
        self._region_key: str = self._session_token_constants.get("regionKey", "")
        # endregion

        # region Read in the attribute defaults
        # Build the MFA serial number string
        self.aws_account_id: str = aws_account_id or self._attribute_defaults.get(
            "defaultAwsAccountId", ""
        )
        self.aws_config_path: str = self._attribute_defaults.get("defaultAwsConfigPath", "").format(
            user=expanduser("~")
        )
        self.aws_credentials_path: str = self._attribute_defaults.get(
            "defaultAwsCredentialsPath", ""
        ).format(user=expanduser("~"))
        self.encoding: str = self._attribute_defaults.get("defaultEncoding", "")
        self.local_namespace: str = self._attribute_defaults.get("defaultLocalNamespace", "")
        self.log_level: str = self._attribute_defaults.get("defaultLogLevel", "")
        self.mfa_token: str = mfa_token or self._attribute_defaults.get("defaultMfaToken", "")
        self.output_format: str = self._attribute_defaults.get("defaultOutputFormat", "")
        self.profile_name: str = profile_name or self._attribute_defaults.get(
            "defaultProfileName", ""
        )
        self.local_kubeconfig_path: str = self._attribute_defaults.get(
            "defaultLocalKubeconfigPath", ""
        ).format(user=expanduser("~"))
        self.kubeconfig_path: str = self._attribute_defaults.get(
            "defaultRancherKubeconfigPath", ""
        ).format(user=expanduser("~"))
        self.rancher_namespace: str = self._attribute_defaults.get("defaultRancherNamespace", "")
        self.region_name: str = self._attribute_defaults.get("defaultRegionName", "")
        self.secret_name: str = self._attribute_defaults.get("defaultSecretName", "")
        self.token_duration: str = self._attribute_defaults.get("defaultTokenDuration", "")
        self.username: str = username or self._attribute_defaults.get("defaultUsername", "")
        # endregion

        # region Populate the constants for arg parsing
        self._CMD_ARG_SCRIPT_CONFIG_PATH = self._argument_parse_constants.get(
            "cmdArgScriptConfigPath", ""
        )
        self._CMD_ARG_AWS_ACCOUNT_ID = self._argument_parse_constants.get("cmdArgAwsAccountId", "")
        self._CMD_ARG_PROFILE_NAME = self._argument_parse_constants.get("cmdArgProfileName", "")
        self._CMD_ARG_USERNAME = self._argument_parse_constants.get("cmdArgUsername", "")
        self._CMD_ARG_MFA_TOKEN = self._argument_parse_constants.get("cmdArgMfaToken", "")
        self._CMD_ARG_AWS_CONFIG_PATH = self._argument_parse_constants.get(
            "cmdArgAwsConfigPath", ""
        )
        self._CMD_ARG_AWS_CREDENTIALS_PATH = self._argument_parse_constants.get(
            "cmdArgAwsCredentialsPath", ""
        )
        self._CMD_ARG_LOCAL_NAMESPACE = self._argument_parse_constants.get(
            "cmdArgLocalNamespace", ""
        )
        self._CMD_ARG_LOG_LEVEL = self._argument_parse_constants.get("cmdArgLogLevel", "")
        self._CMD_ARG_OUTPUT_FORMAT = self._argument_parse_constants.get("cmdArgOutputFormat", "")
        self._CMD_ARG_KUBECONFIG_PATH = self._argument_parse_constants.get(
            "cmdArgKubeconfigPath", ""
        )
        self._CMD_ARG_REGION_NAME = self._argument_parse_constants.get("cmdArgRegionName", "")

        # Populate the constants for shell commands
        self._CMD_FORMAT_KUBECTL_CREATE_SECRET = self._shell_commands.get(
            "cmdFormatKubectlCreateSecret", ""
        )
        self._CMD_FORMAT_GET_SESSION_TOKEN = self._shell_commands.get(
            "cmdFormatGetSessionToken", ""
        )
        self._CMD_FORMAT_GET_LOGIN_PASSWORD_TOKEN = self._shell_commands.get(
            "cmdFormatGetLoginPasswordToken", ""
        )
        # endregion

        # Process the command arguments for further assignment.
        self._cmd_args = self._process_arguments()

        # Initialize our logging
        logging.basicConfig(level=self._cmd_args.log_level.upper())
        logging.debug("Logging initialized.")

        """Override the defaults above with anything which might've been provided as
        command arguments."""
        self.aws_account_id: str = self._cmd_args.aws_account_id
        self.aws_config_path: str = self._cmd_args.aws_config_path
        self.aws_credentials_path: str = self._cmd_args.aws_credentials_path
        self.local_namespace: str = self._cmd_args.local_namespace
        self.log_level: str = self._cmd_args.log_level
        self.kubeconfig_path: str = self._cmd_args.kubeconfig_path
        self.mfa_token: str = self._cmd_args.mfa_token
        self.output_format: str = self._cmd_args.output_format
        self.profile_name: str = self._cmd_args.profile_name
        self.region_name: str = self._cmd_args.region_name
        self.username: str = self._cmd_args.username

        # Get any missing, required values via user input.
        try:
            self._get_user_input(
                aws_account_id=aws_account_id,
                profile_name=profile_name,
                username=username,
                mfa_token=mfa_token,
            )
        except UserInputError:
            input("Failed to obtain authorization.  Press any key to terminate.")
            exit(1)

        self._mfa_serial_number: str = self._session_token_constants.get(
            "mfaSerialNumberTokenized", ""
        ).format(aws_account_id=self.aws_account_id, username=self.username)

    @classmethod
    def _load_script_config(cls, script_config_path: str = None) -> yaml:
        """Load the specified config yaml file.

        Args:
            script_config_path: The path to the config yaml.

        Returns:
            A mapping object representing the yaml.
        """

        if not script_config_path:
            raise MissingConfigError()

        try:
            # Read in the default values
            with open(script_config_path, "r") as config:
                return yaml.safe_load(config)
        except Exception as ex:
            logging.exception(ex)
            raise

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
    def _process_arguments(self) -> argparse.Namespace:
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
            self._CMD_ARG_AWS_ACCOUNT_ID.get("key", ""),
            dest=self._CMD_ARG_AWS_ACCOUNT_ID.get("dest", ""),
            type=str,
            default=self.aws_account_id,
            help=self._CMD_ARG_AWS_ACCOUNT_ID.get("help", "").format(
                aws_account_id=self.aws_account_id
            ),
        )
        parser.add_argument(
            self._CMD_ARG_AWS_CONFIG_PATH.get("key", ""),
            dest=self._CMD_ARG_AWS_CONFIG_PATH.get("dest", ""),
            type=str,
            default=self.aws_config_path,
            help=self._CMD_ARG_AWS_CONFIG_PATH.get("help", "").format(
                aws_config_path=self.aws_config_path
            ),
        )
        parser.add_argument(
            self._CMD_ARG_AWS_CREDENTIALS_PATH.get("key", ""),
            dest=self._CMD_ARG_AWS_CREDENTIALS_PATH.get("dest", ""),
            type=str,
            default=self.aws_credentials_path,
            help=self._CMD_ARG_AWS_CREDENTIALS_PATH.get("help", "").format(
                aws_credentials_path=self.aws_credentials_path
            ),
        )
        parser.add_argument(
            self._CMD_ARG_LOCAL_NAMESPACE.get("key", ""),
            dest=self._CMD_ARG_LOCAL_NAMESPACE.get("dest", ""),
            type=str,
            default=self.local_namespace,
            help=self._CMD_ARG_LOCAL_NAMESPACE.get("help", "").format(
                local_namespace=self.local_namespace
            ),
        )
        parser.add_argument(
            self._CMD_ARG_LOG_LEVEL.get("key", ""),
            dest=self._CMD_ARG_LOG_LEVEL.get("dest", ""),
            type=str,
            default=self.log_level,
            help=self._CMD_ARG_LOG_LEVEL.get("help", "").format(log_level=self.log_level),
        )
        parser.add_argument(
            self._CMD_ARG_MFA_TOKEN.get("key", ""),
            dest=self._CMD_ARG_MFA_TOKEN.get("dest", ""),
            type=str,
            default=self.mfa_token,
            help=self._CMD_ARG_MFA_TOKEN.get("help", "").format(mfa_token=self.mfa_token),
        )
        parser.add_argument(
            self._CMD_ARG_OUTPUT_FORMAT.get("key", ""),
            dest=self._CMD_ARG_OUTPUT_FORMAT.get("dest", ""),
            type=str,
            default=self.output_format,
            help=self._CMD_ARG_OUTPUT_FORMAT.get("help", "").format(
                output_format=self.output_format
            ),
        )
        parser.add_argument(
            self._CMD_ARG_PROFILE_NAME.get("key", ""),
            dest=self._CMD_ARG_PROFILE_NAME.get("dest", ""),
            type=str,
            default=self.profile_name,
            help=self._CMD_ARG_PROFILE_NAME.get("help", "").format(profile_name=self.profile_name),
        )
        parser.add_argument(
            self._CMD_ARG_KUBECONFIG_PATH.get("key", ""),
            dest=self._CMD_ARG_KUBECONFIG_PATH.get("dest", ""),
            type=str,
            default=self.kubeconfig_path,
            help=self._CMD_ARG_KUBECONFIG_PATH.get("help", "").format(
                kubeconfig_path=self.kubeconfig_path
            ),
        )
        parser.add_argument(
            self._CMD_ARG_REGION_NAME.get("key", ""),
            dest=self._CMD_ARG_REGION_NAME.get("dest", ""),
            type=str,
            default=self.region_name,
            help=self._CMD_ARG_REGION_NAME.get("help", "").format(region_name=self.region_name),
        )
        parser.add_argument(
            self._CMD_ARG_USERNAME.get("key", ""),
            dest=self._CMD_ARG_USERNAME.get("dest", ""),
            type=str,
            default=self.username,
            help=self._CMD_ARG_USERNAME.get("help", "").format(username=self.username),
        )

        return parser.parse_args()

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
            aws_account_id: The AWS account ID to use for the token request.
            profile_name: The profile name to enter token details under in the
            credentials and config files.
            username: The username to use for requesting the token.
            mfa_token: The token provided by your MFA device.

        Returns:
            None
        """

        # region Local Functions
        @retry_on_none_or_empty
        def _get_aws_account_id() -> str:
            """Get the AWS account id from the user [has default]."""
            user_input = str(
                input(
                    self._user_input_prompts.get("inputPromptAccountId", "").format(
                        aws_account_id=self.aws_account_id
                    )
                )
            )
            return user_input or self.aws_account_id

        @retry_on_none_or_empty
        def _get_profile_name() -> str:
            """Get the profile name from the user [has default]."""
            return (
                    str(
                        input(
                            self._user_input_prompts.get("inputPromptProfileName", "").format(
                                profile_name=self.profile_name
                            )
                        )
                    )
                    or self.profile_name
            )

        @retry_on_none_or_empty
        def _get_username() -> str:
            """Get the username from the user [has NO default]"""
            return str(input(self._user_input_prompts.get("inputPromptUsername", "")))

        @retry_on_none_or_empty
        def _get_mfa_token() -> str:
            """Get the MFA token from the user [has NO default]"""
            return str(input(self._user_input_prompts.get("inputPromptMfaToken", "")))

        # endregion

        """Get provided command arguments and intersect them with those we require values for.
        The difference between the provided arguments and the required ones is the set of args 
        for which we need to get values."""
        sys_argv = set(sys.argv)
        input_lookup_keys = {
            self._CMD_ARG_USERNAME.get("key", ""),
            self._CMD_ARG_MFA_TOKEN.get("key", ""),
            self._CMD_ARG_AWS_ACCOUNT_ID.get("key", ""),
            self._CMD_ARG_PROFILE_NAME.get("key", ""),
        }
        user_provided_keys = sys_argv.intersection(input_lookup_keys)
        input_keys_to_process = list(input_lookup_keys.difference(user_provided_keys))

        """Get only the missing, required user input.
        Note: In order to support this module being imported, not just run as a script, 
        we also need to filter out any commands passed in to this function by a developer."""
        if not aws_account_id:
            if self._CMD_ARG_AWS_ACCOUNT_ID.get("key", "") in input_keys_to_process:
                self.aws_account_id = _get_aws_account_id()
        else:
            self.aws_account_id = aws_account_id

        if not profile_name:
            if self._CMD_ARG_PROFILE_NAME.get("key", "") in input_keys_to_process:
                self.profile_name = _get_profile_name()
        else:
            self.profile_name = profile_name

        if not username:
            if self._CMD_ARG_USERNAME.get("key", "") in input_keys_to_process:
                self.username = _get_username()
        else:
            self.username = username

        if not mfa_token:
            if self._CMD_ARG_MFA_TOKEN.get("key", "") in input_keys_to_process:
                self.mfa_token = _get_mfa_token()
        else:
            self.mfa_token = _get_mfa_token()

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
            retry_count: The number of times to retry getting the token.

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
        section_name = self._profile_heading_tokenized.format(profile_name=self.profile_name)
        if section_name not in config_.sections():
            config_.add_section(section_name)
        config_[section_name][self._region_key] = self.region_name
        config_[section_name][self._output_key] = self.output_format
        with open(self.aws_config_path, "w") as config_file:
            config_.write(config_file)

    def _build_credentials_file(
            self, access_key_id: str = None, secret_access_key: str = None,
            session_token: str = None
    ) -> None:
        """Writes data to the AWS credentials file.

        Args:
            access_key_id: The access key id value provided by a session token request.
            secret_access_key: The secret access key value provided by a session token request.
            session_token: The session token value provided by a session token request.

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

        credentials[self.profile_name][self._aws_access_key_id_key] = (
                access_key_id or self._access_key_id
        )
        credentials[self.profile_name][self._aws_secret_access_key_key] = (
                secret_access_key or self._secret_access_key
        )
        credentials[self.profile_name][self._aws_session_token_key] = (
                session_token or self._session_token
        )

        with open(self.aws_credentials_path.format(user=expanduser("~")), "w") as credentials_file:
            credentials.write(credentials_file)

    def _build_get_session_token_command(self) -> str:
        """Build the ``aws sts get-session-token`` command.

        For more information, see the AWS documentation on `get_session_token`_.

        Returns:
           A formatted string version of the command to run.

        .. _get_session_token:
            https://docs.aws.amazon.com/cli/latest/reference/sts/get-session-token.html
        """
        command = self._CMD_FORMAT_GET_SESSION_TOKEN.format(
            mfa_serial_number=self._mfa_serial_number,
            mfa_token=self.mfa_token,
            token_duration=self.token_duration,
        ).strip()

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
                kubeconfig=self.kubeconfig_path,
                namespace=self.rancher_namespace,
                encoded_pass=encoded_pass,
            )

    def _build_secret(
            self, kubeconfig: str = None, namespace: str = None, encoded_pass: str = None
    ) -> None:
        """Builds a .dockerconfigjson secret.

        Args:
            kubeconfig: The kubeconfig file to use [default: ~/.kube/config].
            namespace: The namespace in which to install the secret.
            encoded_pass: The base64 password to apply.

        Returns:
            None
        """
        create_secret_command = self._CMD_FORMAT_KUBECTL_CREATE_SECRET.format(
            secret_name=self.secret_name,
            docker_password=encoded_pass,
            aws_account_id=self.aws_account_id,
            kubeconfig=kubeconfig,
            namespace=namespace,
        ).strip()
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
    def update_session_token(self) -> None:
        """Request and apply a new session token.

        This method's main task is to acquire a session token and use it to apply a secret to a
        k8s namespace.
        It does this by doing the following:
            - Get any required values (aws-account_id, profile_name, username, mfa_token) from
              the user.  In order of precedence: defaults < formal parameters < args | input.
            - Request a session token from aws sts get-session-token using subprocess.Popen.
            - Build or update the specified profile section under the credentials and config files.
              This profile contain data which we need in order to push and pull images from our
              AWS ECR server.
            - Call kubectl create secret docker-registry using ''subprocess.Popen''.

        Returns:
            None
        """

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
    """The main routing function.

    This function simply creates an AWSSessionTokenUpdater instance and calls its
    update_session_token method.

    Returns:
        None
    """
    aws_session_token_updater = AWSSessionTokenUpdater()
    aws_session_token_updater.update_session_token()


if __name__ == "__main__":
    """__main__ script hook."""
    main()
