#!/usr/bin/env python3

import boto3
import argparse
import subprocess

# change this path for you own enumerate-iam
# https://github.com/andresriancho/enumerate-iam

enumerate_iam = "/Users/thezakman/Toolz/enumerate-iam/"

title = '''
                    _ 
           dev-0.3 | |
 _ __   ___   ___  | |
| '_ \ / _ \ / _ \ | |
| |_) | (_) | (_) || |
| .__/ \___/ \___/ |_|
| |          ~~DIVER🤿                
|_|        AWS/COGNITO    
-~^~_-~^-~^_~^~^-~^_~-'''

def banner(title):
    print(title)

def get_pool_credentials(region, identity_pool):
    client = boto3.client('cognito-identity', region_name=region)

    _id = client.get_id(IdentityPoolId=identity_pool)
    _id = _id['IdentityId']

    credentials = client.get_credentials_for_identity(IdentityId=_id)
    access_key = credentials['Credentials']['AccessKeyId']
    secret_key = credentials['Credentials']['SecretKey']
    session_token = credentials['Credentials']['SessionToken']
    identity_id = credentials['IdentityId']

    print("\n[Access Key]: " + access_key)
    print("[Secret Key]: " + secret_key, "\n")
    print("[Session Token]: " + session_token, "\n")
    print("[Identity ID]: " + identity_id)

    return access_key, secret_key, region, session_token

def run_enumerate_iam(access_key, secret_key, region, session_token):
    # Execute the subprocess command only if the test flag is provided
    if args.test:
        print("\n🏖️\t[*] Testing out the keys permissions...","\n"+"_"*80)
        subprocess.run(["python3", enumerate_iam + "enumerate-iam.py", "--access-key", access_key, "--secret-key", secret_key, "--region", region, "--session-token", session_token])

# Parse command-line arguments
parser = argparse.ArgumentParser(description='AWS Cognito Information Gatherer')
parser.add_argument('-t', '--test', action='store_true', help='Run the enumerate-iam.py script')
parser.add_argument('-r', '--region', required=True, help='AWS region')
parser.add_argument('-id', '--identity', required=True, help='Cognito Identity Pool ID')
args = parser.parse_args()

banner(title)
access_key, secret_key, region, session_token = get_pool_credentials(args.region, args.identity)
run_enumerate_iam(access_key, secret_key, region, session_token)
