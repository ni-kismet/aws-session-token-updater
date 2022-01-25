import argparse
import configparser
import json
import logging
import subprocess
import sys
from os.path import expanduser
from typing import Callable, Tuple

# region Forward Declarations
LOG_LEVEL: str = "info"
CONFIG_PATH: str = f"{expanduser('~')}/.aws/config"
CREDENTIALS_PATH: str = f"{expanduser('~')}/.aws/credentials"

KUBECONFIG_PATH: str = f"{expanduser('~')}/.kube/config"

LOCAL_KUBECONFIG_PATH: str = f"{expanduser('~')}/.kube/config"
RANCHER_KUBECONFIG_PATH: str = f"{expanduser('~')}/.kube/rancher_kubeconfig.yaml"

PROFILE_NAME: str = "mfa"
USER_NAME: str = ""
PROFILE_CONST: str = "profile "
AWS_ACCOUNT_ID: str = "963234657927"
MFA_SERIAL_NUMBER_TOKENIZED: str = "arn:aws:iam::{aws_account_id}:mfa/{user_name}"
MFA_SERIAL_NUMBER: str = ""
MFA_TOKEN: str = ""
SECRET_HEADER: str = "{aws_account_id}.dkr.ecr.us-east-1.amazonaws.com"
AWS_ACCESS_KEY_ID_KEY: str = "aws_access_key_id"
AWS_SECRET_ACCESS_KEY_KEY: str = "aws_secret_access_key"
AWS_SESSION_TOKEN_KEY: str = "aws_session_token"
REGION_KEY: str = "region"
OUTPUT_KEY: str = "output"
REGION_NAME: str = "us-east-1"
OUTPUT_FORMAT: str = "json"
LOCAL_NAMESPACE: str = "default"
RANCHER_NAMESPACE: str = "systemlink-testinsights"
SECRET_NAME: str = "aws-ecr-secret"
ARGS: argparse.Namespace = argparse.Namespace()
ACCESS_KEY_ID: str = ""
SECRET_ACCESS_KEY: str = ""
SESSION_TOKEN: str = ""
TOKEN_DURATION: str = "129600"
ENCODING: str = "utf=8"

# This command structure lets kubectl build the secret yaml for us and just pass it in to apply as file-like input.
# This is necessary for the case where we're updating an existing secret from the terminal.
KUBECTL_CREATE_SECRET_LOCAL_CMD: str = (
    "kubectl create secret docker-registry {secret_name} --docker-username=AWS "
    "--docker-password={docker_password} --docker-server={aws_account_id}.dkr.ecr."
    "us-east-1.amazonaws.com --dry-run=client -o yaml | kubectl apply -f -"
)

# This command structure lets kubectl build the secret yaml for us and just pass it in to apply as file-like input.
# This is necessary for the case where we're updating an existing secret from the terminal.
KUBECTL_CREATE_SECRET_CMD: str = (
    "kubectl create secret docker-registry {secret_name} --docker-username=AWS "
    "--docker-password={docker_password} --docker-server={aws_account_id}.dkr.ecr."
    "us-east-1.amazonaws.com --dry-run=client -o yaml | kubectl apply --kubeconfig "
    "{kubeconfig} -n {namespace} -f -"
)

# This command gets a session token from AWS.
GET_SESSION_TOKEN_CMD: str = (
    "aws sts get-session-token --serial-number {mfa_serial_number} "
    "--token-code {mfa_token} --duration-seconds {token_duration}"
)


def set_account_id(value: str = None) -> None:
    """Setter for AWS_ACCOUNT_ID.

    Args:
        value (str): The value to assign.

    Returns:
        None
    """
    global AWS_ACCOUNT_ID
    AWS_ACCOUNT_ID = value


def set_profile_name(value: str = None) -> None:
    """Setter for PROFILE_NAME.

    Args:
        value (str): The value to assign.

    Returns:
        None
    """
    global PROFILE_NAME
    PROFILE_NAME = value


def set_user_name(value: str = None) -> None:
    """Setter for USER_NAME.

    Args:
        value (str): The value to assign.

    Returns:
        None
    """
    global USER_NAME
    USER_NAME = value


def set_mfa_token(value: str = None) -> None:
    """Setter for MFA_TOKEN.

    Args:
        value (str): The value to assign.

    Returns:
        None
    """
    global MFA_TOKEN
    MFA_TOKEN = value


INPUT_LOOKUP = {
    "--account-id": {
        "user_prompts": {
            "user_prompt": f"Enter your AWS account Id [{AWS_ACCOUNT_ID}]: ",
        },
        "logging_token_strings": {
            "val_from_args_message": f"Using account-id from args: {AWS_ACCOUNT_ID}",
            "val_from_user_message": f"Using account-id from user: {AWS_ACCOUNT_ID}",
            "empty_value_log_message": "User provided an empty account-id value.",
        },
        "default": AWS_ACCOUNT_ID,
        "destination": set_account_id,
    },
    "--profile-name": {
        "user_prompts": {
            "user_prompt": f"Enter the name of the profile to modify [{PROFILE_NAME}]: ",
        },
        "logging_token_strings": {
            "val_from_args_message": f"Using profile-name from args: {PROFILE_NAME}",
            "val_from_user_message": f"Using profile-name from user: {PROFILE_NAME}",
            "empty_value_log_message": "User provided an empty profile-name value.",
        },
        "default": PROFILE_NAME,
        "destination": set_profile_name,
    },
    "--user-name": {
        "user_prompts": {
            "user_prompt": f"Enter your user name: ",
            "blank_name_message": "User name may not be blank.",
        },
        "logging_token_strings": {
            "val_from_args_message": f"Using user-name from args: {USER_NAME}",
            "val_from_user_message": f"Using user-name from user: {USER_NAME}",
            "empty_value_log_message": "User provided an empty user-name value.",
        },
        "default": None,
        "destination": set_user_name,
    },
    "--mfa-token": {
        "user_prompts": {
            "user_prompt": f"Enter your MFA token value: ",
            "empty_value_message": "MFA token may not be blank.",
        },
        "logging_token_strings": {
            "val_from_args_message": f"Using mfa-token from args: {MFA_TOKEN}",
            "empty_value_log_message": "User provided an empty mfa-token value.",
        },
        "default": None,
        "destination": set_mfa_token,
    },
}
# endregion


class SessionTokenError(Exception):
    """There was an error getting an AWS session token."""


class RetryWarning(Exception):
    """There was an issue, so we're retrying."""


class UserInputError(Exception):
    """The user failed to enter valid input in the set number of tries."""


def process_arguments() -> None:
    """Processes commandline arguments."""
    global ARGS

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--account-id",
        dest="account_id",
        type=str,
        default=AWS_ACCOUNT_ID,
        help=f"The account you wish to get a session token from [{AWS_ACCOUNT_ID}].",
    )
    parser.add_argument(
        "--config-path",
        dest="config_path",
        type=str,
        default=CONFIG_PATH,
        help=f"The path to your AWS config file [{CONFIG_PATH}].",
    )
    parser.add_argument(
        "--credentials-path",
        dest="credentials_path",
        type=str,
        default=CREDENTIALS_PATH,
        help=f"The path to your AWS credentials file [{CREDENTIALS_PATH}].",
    )
    parser.add_argument(
        "--kubeconfig",
        dest="kubeconfig",
        type=str,
        default=KUBECONFIG_PATH,
        help=f"The path to a Rancher kubeconfig YAML file [{KUBECONFIG_PATH}].",
    )
    parser.add_argument(
        "--log-level",
        dest="log_level",
        type=str,
        default=LOG_LEVEL,
        help=f"The logging level to use [{LOG_LEVEL}].",
    )
    parser.add_argument(
        "--output-format",
        dest="output_format",
        type=str,
        default=OUTPUT_FORMAT,
        help=f"The output format for AWS auth requests [{OUTPUT_FORMAT}].",
    )
    parser.add_argument(
        "--profile-name",
        dest="profile_name",
        type=str,
        default=PROFILE_NAME,
        help=f"The name of the profile section to work with [{PROFILE_NAME}].",
    )
    parser.add_argument(
        "--region-name",
        dest="region_name",
        type=str,
        default=REGION_NAME,
        help=f"The AWS region where you wish to work [{REGION_NAME}].",
    )
    parser.add_argument(
        "--user-name",
        dest="user_name",
        type=str,
        default=USER_NAME,
        help=f"The username to supply for the token request [{USER_NAME}].",
    )
    parser.add_argument(
        "--mfa-token",
        dest="mfa_token",
        type=str,
        default=MFA_TOKEN,
        help="The MFA token supplied by your authenticator app [''].",
    )

    ARGS = parser.parse_args()


def initialize_globals() -> None:
    """Sets the values of the script's globals.

    Returns:
        None
    """
    global AWS_ACCOUNT_ID
    global CONFIG_PATH
    global CREDENTIALS_PATH
    global KUBECONFIG_PATH
    global LOG_LEVEL
    global MFA_SERIAL_NUMBER
    global OUTPUT_FORMAT
    global PROFILE_NAME
    global REGION_NAME
    global USER_NAME

    logging.basicConfig(level=ARGS.log_level.upper())
    logging.debug("Logging initialized.")

    AWS_ACCOUNT_ID = ARGS.account_id
    CONFIG_PATH = ARGS.config_path
    CREDENTIALS_PATH = ARGS.credentials_path
    KUBECONFIG_PATH = ARGS.kubeconfig
    LOG_LEVEL = ARGS.log_level
    OUTPUT_FORMAT = ARGS.output_format
    PROFILE_NAME = ARGS.profile_name
    REGION_NAME = ARGS.region_name
    USER_NAME = ARGS.user_name

    MFA_SERIAL_NUMBER = MFA_SERIAL_NUMBER_TOKENIZED.format(
        aws_account_id=AWS_ACCOUNT_ID, user_name=USER_NAME
    )
    logging.debug(f"MFA Serial Number: {MFA_SERIAL_NUMBER}")

    # Get any necessary user inputs to store to globals.
    get_user_input()


def get_auth(retry_count: int = 3):  # -> Tuple[str, str, str]
    """Gets the AWS session token object based on your username and MFA token.

    Args:
        retry_count (int): The number of times to retry getting the token.

    Returns:
        Output (Tuple[str, str, str]): Returns the pertinent data
            for the ~/.aws/.credentials section specified by profile name in the
            form of a tuple(aws_secret_access_key, aws_access_key_id, aws_session_token).
    """
    # region globals
    global PROFILE_NAME
    global AWS_ACCOUNT_ID
    global ACCESS_KEY_ID
    global SECRET_ACCESS_KEY
    global USER_NAME
    global MFA_TOKEN
    global SESSION_TOKEN
    # endregion

    # Give the user `retry_count` tries to get their token.
    for count in range(retry_count, 0, -1):
        try:
            # Build and run the command to get the session token.
            command = build_get_session_token_command()
            stderr, stdout = run_shell_command(command)

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
                ACCESS_KEY_ID = session_token_obj.get("Credentials", {}).get(
                    "AccessKeyId", ""
                )
                logging.debug(f"access_key_id: {ACCESS_KEY_ID}")

                # Pull out the SecretAccessKey to enter into the credentials file.
                SECRET_ACCESS_KEY = session_token_obj.get("Credentials", {}).get(
                    "SecretAccessKey", ""
                )
                logging.debug(f"secret_access_key: {SECRET_ACCESS_KEY}")

                # Pull out the SessionToken to enter into the credentials file.
                SESSION_TOKEN = session_token_obj.get("Credentials", {}).get(
                    "SessionToken", ""
                )
                logging.debug(f"session_token: {SESSION_TOKEN}")

                # We're done, so return to caller.
                return
            # Kick it around for another try.
            continue
        except RetryWarning as retry_warning:
            """Session Token Acquisition Loop Handler

            Use this exception to handle any command issues which only need retries.
            """
            logging.warning(retry_warning)
            MFA_TOKEN = str(
                input(f"Enter your MFA token value ({count - 1} tries remain): ")
            )
        except Exception as ex:
            """Session Token Acquisition Loop Catch-all

            Use this exception to handle any command issues which require loop termination.
            """
            logging.exception(ex)
            raise

    raise SessionTokenError()


def run_shell_command(command) -> Tuple[str, str]:
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


def build_get_session_token_command() -> str:
    """Build the command to execute.

    Returns:
        (str): A formatted string version of the command to run.
    """
    command = GET_SESSION_TOKEN_CMD.format(
        mfa_serial_number=MFA_SERIAL_NUMBER_TOKENIZED.format(
            aws_account_id=AWS_ACCOUNT_ID, user_name=USER_NAME
        ),
        mfa_token=MFA_TOKEN,
        token_duration=TOKEN_DURATION,
    )
    logging.debug(f"Command to execute: {command}")
    return command


def get_user_input() -> None:
    """Get input values from the user.

    Returns:
        None
    """
    global AWS_ACCOUNT_ID, PROFILE_NAME, USER_NAME, MFA_TOKEN

    num_retries = 3
    sys_argv = set(sys.argv)
    input_lookup_keys = set(INPUT_LOOKUP.keys())
    user_provided_keys = sys_argv.intersection(input_lookup_keys)
    input_keys_to_process = list(input_lookup_keys.difference(user_provided_keys))

    logging.debug(input_keys_to_process)

    for input_key in input_keys_to_process:
        input_data_object = INPUT_LOOKUP[input_key]
        user_prompts = input_data_object.get("user_prompts", {})
        logging_token_strings = input_data_object.get("logging_token_strings", {})
        default = input_data_object.get("default", None)
        destination = input_data_object.get("destination", Callable[[str], None])

        if not default:
            """The user must supply a value or terminate."""
            for try_num in range(num_retries, 0, -1):
                user_input = str(input(user_prompts.get("user_prompt", default)))
                if not user_input:
                    print(user_prompts.get("empty_value_message"), f"{try_num} tries remain.")
                    logging.debug(logging_token_strings.get("empty_value_log_message", ""))
                    if try_num <= 0:
                        raise UserInputError()
                    continue
                destination(user_input)
                break
        else:
            """There is a default value to fall back on."""
            input_data_object["destination"] = str(input(user_prompts.get("user_prompt", default))) or destination
            logging.debug(logging_token_strings.get("val_from_user_message"))


def build_config_file() -> None:
    """Writes data to the AWS config file.

    Returns:
        None
    """
    config_ = configparser.ConfigParser()
    config_.read(CONFIG_PATH)
    section_name = f"{PROFILE_CONST}{PROFILE_NAME}"
    if section_name not in config_.sections():
        config_.add_section(section_name)
    config_[section_name][REGION_KEY] = REGION_NAME
    config_[section_name][OUTPUT_KEY] = OUTPUT_FORMAT
    with open(CONFIG_PATH, "w") as config_file:
        config_.write(config_file)


def build_credentials_file() -> None:
    """Writes data to the AWS credentials file.

    Returns:
        None
    """
    credentials = configparser.ConfigParser()

    # If the file doesn't exist, .read() will create it.
    credentials.read(CREDENTIALS_PATH)

    if PROFILE_NAME not in credentials.sections():
        credentials.add_section(PROFILE_NAME)

    credentials[PROFILE_NAME][AWS_ACCESS_KEY_ID_KEY] = ACCESS_KEY_ID
    credentials[PROFILE_NAME][AWS_SECRET_ACCESS_KEY_KEY] = SECRET_ACCESS_KEY
    credentials[PROFILE_NAME][AWS_SESSION_TOKEN_KEY] = SESSION_TOKEN
    with open(CREDENTIALS_PATH, "w") as credentials_file:
        credentials.write(credentials_file)


def build_secrets() -> None:
    """Creates a .dockerconfigjson secret with either the local .kube/config or the provided one.

    Returns:
        None
    """
    # Get the login password for the mfa profile we wrote before.
    subprocess_ = subprocess.Popen(
        f"aws ecr get-login-password --profile {PROFILE_NAME}",
        shell=True,
        stdout=subprocess.PIPE,
    )
    encoded_pass = subprocess_.stdout.read().decode(ENCODING).strip()

    if "--kubeconfig" not in sys.argv:
        # Build the local secret.
        build_secret(
            kubeconfig=LOCAL_KUBECONFIG_PATH,
            namespace=LOCAL_NAMESPACE,
            encoded_pass=encoded_pass,
        )
    else:
        # Build the rancher secret.
        build_secret(
            kubeconfig=RANCHER_KUBECONFIG_PATH,
            namespace=RANCHER_NAMESPACE,
            encoded_pass=encoded_pass,
        )


def build_secret(kubeconfig: str = None, namespace: str = None, encoded_pass: str = None) -> None:
    """Builds a .dockerconfigjson secret.

    Args:
        kubeconfig (str): The kubeconfig file to use (defaults to ~/.kube/config).
        namespace (str): The namespace in which to install the secret.
        encoded_pass (str): The base64 password to apply.

    Returns:
        None
    """
    create_secret_command = KUBECTL_CREATE_SECRET_CMD.format(
        secret_name=SECRET_NAME,
        docker_password=encoded_pass,
        aws_account_id=AWS_ACCOUNT_ID,
        kubeconfig=kubeconfig,
        namespace=namespace,
    )
    subprocess_ = subprocess.Popen(
        create_secret_command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = subprocess_.stdout.read().decode(ENCODING).strip()
    logging.debug(output)


def main() -> None:
    """The main starting point.

    Returns:
        None
    """
    process_arguments()

    try:
        initialize_globals()
    except UserInputError:
        input("Failed to obtain authorization.  Press any key to terminate.")

    try:
        get_auth()
    except SessionTokenError:
        input("Failed to obtain authorization.  Press any key to terminate.")

    build_credentials_file()
    build_config_file()
    build_secrets()


if __name__ == "__main__":
    main()
