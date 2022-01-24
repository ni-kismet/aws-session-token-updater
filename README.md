# aws_session_token_rotator
 A python utility script for rotating the password in the aws-ecr-secret locally and on Rancher (if you supply a rancher config.yaml).

 You may run this script in multiple ways...
 * Run with no options for the default behaviour.  The script will prompt you for any necessary values, then create the local secret.
   <br>`python.exe -c auto_access_key_rotator.py`
 * Supply the --kubeconfig flag in order to update the secret on rancher.
   <br>`python.exe -c auto_access_key_rotator.py --kubeconfig ~/.kube/rancher_kubeconfig.yaml -n systemlink-testinsights`
 * To see all available command arguments, run the following:
     <br>`python.exe -c auto_access_key_rotator.py --help`

