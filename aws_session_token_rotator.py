import argparse
import base64
import configparser
import json
import logging
import subprocess
from typing import Tuple
from kubernetes import client, config
import boto3
from botocore.exceptions import ClientError
from os.path import expanduser
from kubernetes.client import ApiException, V1Secret

LOG_LEVEL: str = "warning"
CONFIG_PATH: str = f"{expanduser('~')}/.aws/config"
CREDENTIALS_PATH: str = f"{expanduser('~')}/.aws/credentials"
LOCAL_KUBECONFIG_PATH: str = f"{expanduser('~')}/.kube/config"
RANCHER_KUBECONFIG_PATH: str = f"{expanduser('~')}/.kube/rancher_kubeconfig.yaml"
PROFILE_NAME: str = "mfa"
USER_NAME: str = ""
PROFILE_CONST: str = "profile "
AWS_ACCOUNT_ID: str = "963234657927"
MFA_SERIAL_NUMBER: str = "arn:aws:iam::{aws_account_id}:mfa/{user_name}"
SECRET_HEADER: str = "{aws_account_id}.dkr.ecr.us-east-1.amazonaws.com"
AWS_ACCESS_KEY_ID_KEY: str = "aws_access_key_id"
AWS_SECRET_ACCESS_KEY_KEY: str = "aws_secret_access_key"
AWS_SESSION_TOKEN_KEY: str = "aws_session_token"
REGION_KEY: str = "region"
OUTPUT_KEY: str = "output"
REGION_VALUE: str = "us-east-1"
OUTPUT_FORMAT: str = "json"
LOCAL_NAMESPACE: str = "default"
RANCHER_NAMESPACE: str = "systemlink-testinsights"
SECRET_NAME: str = "aws-ecr-secret"
ARGS: argparse.Namespace = argparse.Namespace()


class SessionTokenError(Exception):
    """There was an error getting an AWS session token."""


def process_arguments() -> None:
    """Processes commandline arguments."""
    global ARGS

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--account-id", dest="account_id",
        default=AWS_ACCOUNT_ID,
        help=f"The account you wish to get a session token from [{AWS_ACCOUNT_ID}]."
    )
    parser.add_argument(
        "--config-path", dest="config_path",
        default=CONFIG_PATH,
        help=f"The path to your AWS config file [{CONFIG_PATH}]."
    )
    parser.add_argument(
        "--credentials-path", dest="credentials_path",
        default=CREDENTIALS_PATH,
        help=f"The path to your AWS credentials file [{CREDENTIALS_PATH}]."
    )
    parser.add_argument(
        "--kubeconfig", dest="kubeconfig",
        default="",
        help="The path to a Rancher kubeconfig YAML file ['']."
    )
    parser.add_argument(
        "--log-level", dest="log_level",
        default=LOG_LEVEL,
        help=f"The logging level to use [{LOG_LEVEL}]."
    )
    parser.add_argument(
        "--output-format", dest="output_format",
        default=OUTPUT_FORMAT,
        help=f"The output format for AWS auth requests [{OUTPUT_FORMAT}]."
    )
    parser.add_argument(
        "--profile-name", dest="profile_name",
        default=PROFILE_NAME,
        help=f"The name of the profile section to work with [{PROFILE_NAME}]."
    )
    parser.add_argument(
        "--region-name", dest="region_name",
        default=REGION_VALUE,
        help=f"The AWS region where you wish to work [{REGION_VALUE}]."
    )
    parser.add_argument(
        "--user-name", dest="user_name",
        default=USER_NAME,
        help="The username to supply for the token request ['']."
    )

    ARGS = parser.parse_args()


def set_globals() -> None:
    """Sets the values of the script's globals.

    Returns:
        None
    """
    global AWS_ACCOUNT_ID
    global CONFIG_PATH
    global CREDENTIALS_PATH
    global LOG_LEVEL
    global OUTPUT_FORMAT
    global PROFILE_NAME
    global REGION_VALUE
    global USER_NAME

    CONFIG_PATH = f"{expanduser('~')}/.aws/config"
    CREDENTIALS_PATH = f"{expanduser('~')}/.aws/credentials"

    logging.basicConfig(level=ARGS.log_level.upper())
    logging.info("Logging initialized.")

    AWS_ACCOUNT_ID = ARGS.account_id
    CONFIG_PATH = ARGS.config_path
    CREDENTIALS_PATH = ARGS.credentials_path
    LOG_LEVEL = ARGS.log_level
    OUTPUT_FORMAT = ARGS.output_format
    PROFILE_NAME = ARGS.profile_name
    REGION_VALUE = ARGS.region_name
    USER_NAME = ARGS.user_name


def get_auth(retry_count: int = 3) -> Tuple[str, str, str]:
    """Gets the AWS session token object based on your username and MFA token.

    Args:
        retry_count (int): The number of times to retry getting the token.

    Returns:
        Output (Tuple[str, str, str]): Returns the pertinent data
            for the ~/.aws/.credentials section specified by profile name in the
            form of a tuple(aws_secret_access_key, aws_access_key_id, aws_session_token).
    """
    global PROFILE_NAME
    token_code: str = ""
    username: str = ""
    client_sts = boto3.client("sts")

    account_id = (
            str(input(f"Please enter your AWS account Id [{AWS_ACCOUNT_ID}]: "))
            or AWS_ACCOUNT_ID
    )
    PROFILE_NAME = (
            str(input(f"Enter the name of the profile to modify [{PROFILE_NAME}]: "))
            or PROFILE_NAME
    )

    for count in range(3):
        username = str(input("Enter your username: "))
        if username:
            break
        if count >= 2:
            raise SessionTokenError()
        print("Username may not be blank.")

    for count in range(3):
        token_code = str(input("Enter your MFA token value: "))
        if token_code:
            break
        if count >= 2:
            raise SessionTokenError()
        print("MFA token may not be blank.")

    for count in range(retry_count, 0, -1):
        try:
            response = client_sts.get_session_token(
                DurationSeconds=129600,
                SerialNumber=MFA_SERIAL_NUMBER.format(
                    aws_account_id=account_id, user_name=username
                ),
                TokenCode=token_code,
            )
            access_key_id = response.get("Credentials", {}).get("AccessKeyId", "")
            secret_access_key = response.get("Credentials", {}).get(
                "SecretAccessKey", ""
            )
            session_token = response.get("Credentials", {}).get("SessionToken", "")
            logging.debug(f"access_key_id: {access_key_id}")
            logging.debug(f"secret_access_key: {secret_access_key}")
            logging.debug(f"session_token: {session_token}")
            return access_key_id, secret_access_key, session_token
        except ClientError as client_error:
            print(client_error)
            token_code = str(
                input(f"Enter your MFA token value ({count - 1} tries remain): ")
            )
    raise SessionTokenError()


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
    config_[section_name][REGION_KEY] = REGION_VALUE
    config_[section_name][OUTPUT_KEY] = OUTPUT_FORMAT
    with open(CONFIG_PATH, "w") as config_file:
        config_.write(config_file)


def build_credentials_file(
        access_key_id: str = None, secret_access_key: str = None, session_token: str = None
) -> None:
    """Writes data to the AWS credentials file.

    Args:
        access_key_id (str): Specifies the AWS access key used as part of the credentials
            to authenticate the command request.
        secret_access_key (str): Specifies the AWS secret key used as part of the credentials
            to authenticate the command request.
        session_token (str): Specifies an AWS session token. A session token is required only
            if you manually specify temporary security credentials.

    Returns:
        None
    """
    credentials = configparser.ConfigParser()

    # If the file doesn't exist, .read() will create it.
    credentials.read(CREDENTIALS_PATH)

    if PROFILE_NAME not in credentials.sections():
        credentials.add_section(PROFILE_NAME)

    credentials[PROFILE_NAME][AWS_ACCESS_KEY_ID_KEY] = access_key_id
    credentials[PROFILE_NAME][AWS_SECRET_ACCESS_KEY_KEY] = secret_access_key
    credentials[PROFILE_NAME][AWS_SESSION_TOKEN_KEY] = session_token
    with open(CREDENTIALS_PATH, "w") as credentials_file:
        credentials.write(credentials_file)


def update_secrets() -> None:
    """Update the local and (if --kubeconfig is provided) the Rancher k8s aws-ecr-secret secret."""
    # Get the login password for the mfa profile we wrote before.
    subprocess_ = subprocess.Popen(
        f"aws ecr get-login-password --profile {PROFILE_NAME}", shell=True, stdout=subprocess.PIPE
    )

    # Build the secret's body.
    body = build_secret_body(encoded_pass=subprocess_.stdout.read().strip())

    # Build the secrets.
    build_local_secret(body=body)

    # If the user passed in the --kubeconfig file path, then build the rancher secret as well.
    if ARGS.kubeconfig:
        build_rancher_secret(body=body)


def build_local_secret(body: V1Secret = None, pretty: bool = True) -> None:
    """Build the local secret.

    Args:
        body (V1Secret): The secret to apply locally.
        pretty (bool): Whether to pretty print.

    Returns:
        None
    """
    # Load the local kube config.
    config.load_kube_config(LOCAL_KUBECONFIG_PATH)
    core_api_instance = client.CoreV1Api()

    # Check for the local secret and write its data.
    local_secret = core_api_instance.read_namespaced_secret(SECRET_NAME, LOCAL_NAMESPACE)
    logging.debug(local_secret.data)

    try:
        if not local_secret:
            api_response = core_api_instance.create_namespaced_secret(
                namespace=LOCAL_NAMESPACE, body=body, pretty=pretty
            )
        else:
            api_response = core_api_instance.replace_namespaced_secret(
                name=SECRET_NAME, namespace=LOCAL_NAMESPACE, body=body)
        logging.debug(api_response.data)
    except ApiException as api_exception:
        logging.exception(api_exception)
        raise


def build_rancher_secret(body: V1Secret = None, pretty: bool = True):
    """Build the rancher secret.

    Args:
        body (V1Secret): The secret to apply locally.
        pretty (bool): Whether to pretty print.

    Returns:
        None
    """
    # Check for the rancher secret.
    config.load_kube_config(RANCHER_KUBECONFIG_PATH)
    core_api_instance = client.CoreV1Api()

    # Check for the remote secret and write its data.
    rancher_secret = core_api_instance.read_namespaced_secret(name=SECRET_NAME, namespace=RANCHER_NAMESPACE)
    logging.debug(rancher_secret.data)

    try:
        if not rancher_secret:
            api_response = core_api_instance.create_namespaced_secret(
                namespace=RANCHER_NAMESPACE, body=body, pretty=pretty
            )
        else:
            api_response = core_api_instance.replace_namespaced_secret(
                name=SECRET_NAME, namespace=RANCHER_NAMESPACE, body=body)
        logging.debug(api_response)
    except ApiException as api_exception:
        logging.exception(api_exception)
        raise


def build_secret_body(encoded_pass: bytes = None) -> V1Secret:
    """Build the body of the new secret.

    Args:
        encoded_pass (str): The

    Returns:
        V1Secret: A populated V1Secret instance.
    """
    body = client.V1Secret()
    body.api_version = 'v1'
    body.kind = 'Secret'
    body.metadata = {"name": SECRET_NAME}
    body.type = "kubernetes.io/dockerconfigjson"
    body_json = {
        "auths": {
            SECRET_HEADER.format(aws_account_id=AWS_ACCOUNT_ID): {
                "auth": AWS_SESSION_TOKEN_KEY,
                "password": encoded_pass.decode("utf-8"),
                "username": "AWS"
            }
        }
    }
    body.data = {".dockerconfigjson": base64.b64encode(json.dumps(body_json).encode("utf-8")).decode("utf-8")}
    return body


def main() -> None:
    """The main starting point.

    Returns:
        None
    """
    process_arguments()
    set_globals()

    access_key_id: str = ""
    secret_access_key: str = ""
    session_token: str = ""

    try:
        access_key_id, secret_access_key, session_token = get_auth()
    except SessionTokenError:
        input("Failed to obtain authorization.  Press any key to terminate.")

    build_credentials_file(access_key_id, secret_access_key, session_token)
    build_config_file()

    update_secrets()


if __name__ == "__main__":
    main()
