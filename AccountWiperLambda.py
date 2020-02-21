 ####
 # Customized AWS Org Account wiping solution
 #
 # This python package is expected to be launched via an AWS Service Catalog
 # published account wipe application in the ORG Master account.
 # 
 # Code created by Mark Colatosti
 #
 #### 

#!/usr/bin/env python

from __future__ import print_function

import argparse
import ast
import boto3
import botocore
import configparser
import json
import logging
import os
import time
import sys
import textwrap
import urllib

from botocore.vendored import requests

SUCCESS = "SUCCESS"
FAILED = "FAILED"
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Function to send custom lambda function results back to cloudformation service
def send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False):
    responseUrl = event['ResponseURL']

    print(responseUrl)

    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)

    print("Response body:\n" + json_responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))

def assume_role(account_id, account_role):
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            assumedRoleObject = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="NewAccountRole"
            )
        except botocore.exceptions.ClientError as e:
            assuming_role = True
            print(e)
            print("Retrying...")
            time.sleep(60)

    # From the response that contains the assumed role, return the temporary
    # credentials that can be used to make subsequent API calls
    return assumedRoleObject['Credentials']

def attach_policy(rolename,policyarn,credentials):
    iam_client = boto3.client('iam',aws_access_key_id=credentials['AccessKeyId'],
                                  aws_secret_access_key=credentials['SecretAccessKey'],
                                  aws_session_token=credentials['SessionToken'])
    attempt_counter = 1   #Try 3 times, every 30 secs for a maximum of 90 sec. 
    response="Failure"
    while attempt_counter <= 3:
        try:
            response = iam_client.attach_role_policy(RoleName=rolename,PolicyArn=policyarn)
            print("Success policy {} to role {} on attempt#{}".format(policyarn,rolename,attempt_counter))
            print(response)
            
        except botocore.exceptions.ClientError as e:    
            print("Error Occured in attempt #{}, attaching policy to role : {}".format(attempt_counter,e))
            time.sleep(30)
        else:
            attempt_counter = 999
        attempt_counter += 1
    return response

def get_client(service):
    client = boto3.client(service)
    return client

def create_newrole(newrole,newrolepolicy,newtrustpolicy):
    iam_client = boto3.client('iam')
    print(newrolepolicy)
    print(newtrustpolicy)
    
    attempt_counter = 1   #Try 20 times, every 30 secs for a maximum of 10 min. 
    while attempt_counter <= 3:
        try:
            create_role_response = iam_client.create_role(RoleName=newrole,AssumeRolePolicyDocument=newtrustpolicy,Description=newrole,MaxSessionDuration=3600)
            print("Success creating new role on attempt#{}".format(attempt_counter))
            print(create_role_response['Role']['Arn'])
            
        except botocore.exceptions.ClientError as e:    
            print("Error Occured in attempt #{}, creating a role : {}".format(attempt_counter,e))
            create_role_response['Role']['Arn']="Problem Creating Role."
            time.sleep(10)
        else:
            attempt_counter = 999
        attempt_counter += 1

    attempt_counter = 1   #Try 20 times, every 30 secs for a maximum of 10 min. 
    while attempt_counter <= 20:
        try:
            update_role_response = iam_client.put_role_policy(RoleName=newrole,PolicyName=newrole,PolicyDocument=newrolepolicy)
        except botocore.exceptions.ClientError as e:
            print("Error on attempt# {}, attaching policy to the role : {}".format(attempt_counter,e))
        else:
            print("Success on attempt# {}, attaching policy to the role".format(attempt_counter))
            attempt_counter = 999
        attempt_counter += 1

    print(newrole)
    return create_role_response['Role']['Arn']

def selfinvoke(event,status):
    lambda_client = boto3.client('lambda')
    function_name = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    event['RequestType'] = status
    print('invoking itself ' + function_name)
    response = lambda_client.invoke(FunctionName=function_name, InvocationType='Event',Payload=json.dumps(event))

def role_inlinepolicy(requestype,credentials,awsrolename,policyname,awsrolepolicy):
    iam_client = boto3.client('iam',aws_access_key_id=credentials['AccessKeyId'],
                                    aws_secret_access_key=credentials['SecretAccessKey'],
                                    aws_session_token=credentials['SessionToken'])
    if (requestype == "add"):
        print("--- Adding to IAM policy ---")
        attempt_counter = 1   #Try 20 times, every 30 secs for a maximum of 10 min. 
        while attempt_counter <= 20:
            try:
                update_role_response = iam_client.put_role_policy(RoleName=awsrolename,PolicyName=policyname,PolicyDocument=awsrolepolicy)
            except botocore.exceptions.ClientError as e:
                print("Error on attempt# {}, attaching policy to the role : {}".format(attempt_counter,e))
            else:
                print("Success on attempt# {}, attaching policy to the role".format(attempt_counter))
                attempt_counter = 999
            attempt_counter += 1
        return update_role_response

def create_codebuildproject(wipeaccountid,root_id):
    client = boto3.client('codebuild')
    response = client.create_project(
        name='AccountWipe_' + wipeaccountid +'',
        description='Builds a container for the purposes of running AWS-Nuke for wiping the account specified.',
        artifacts={
            'type': 'NO_ARTIFACTS'
        },
        badgeEnabled=False,
        environment={
            'computeType': 'BUILD_GENERAL1_SMALL',
            'image': 'aws/codebuild/docker:18.09.0',
            'imagePullCredentialsType': 'CODEBUILD',
            'privilegedMode': True,
            'type': 'LINUX_CONTAINER',
            'environmentVariables': [
                {
                    "name": "AssumeRoleName",
                    "type": "PLAINTEXT",
                    "value": "OrganizationAccountAccessRole"
                },
                {
                    "name": "WipeAccountId",
                    "type": "PLAINTEXT",
                    "value": wipeaccountid
                }
            ]
        },
        logsConfig={
            'cloudWatchLogs': {
                'groupName': "accountwiper_"+wipeaccountid+"",
                'status': 'ENABLED'
            }
        },
        serviceRole="arn:aws:iam::"+ root_id + ":role/accountwiper_codebuildrole_"+wipeaccountid+"",
        source={
            'type': 'NO_SOURCE',
            'buildspec': """
                version: 0.2
                phases:
                  install:
                    commands:
                      - apt-get install jq
                      - wget -q https://github.com/rebuy-de/aws-nuke/releases/download/v2.10.0/aws-nuke-v2.10.0-linux-amd64
                      - mv aws-nuke-v2.10.0-linux-amd64 /bin/aws-nuke
                      - chmod +x /bin/aws-nuke
                  build:
                    commands:
                      - aws s3 cp s3://iac-appcatalog/account-wipe/aws-nuke-config.yaml .
                      -   |
                          account_id=$WipeAccountId
                          echo "Assuming Role for Account $account_id";
                          aws sts assume-role --role-arn arn:aws:iam::$account_id:role/${AssumeRoleName} --role-session-name account-$account_id --query "Credentials" > $account_id.json;
                          cat $account_id.json
                          ACCESS_KEY_ID=$(cat $account_id.json |jq -r .AccessKeyId);
                          SECRET_ACCESS_KEY=$(cat $account_id.json |jq -r .SecretAccessKey);
                          SESSION_TOKEN=$(cat $account_id.json |jq -r .SessionToken);
                          cp aws-nuke-config.yaml $account_id.yaml;
                          sed -i -e "s/000000000000/$account_id/g" $account_id.yaml;
                          echo "Configured aws-nuke-config.yaml";
                          echo "Running Nuke on Account $account_id";
                          # TODO: Add --no-dry-run flag for Production
                          aws-nuke -c $account_id.yaml --force --access-key-id $ACCESS_KEY_ID --secret-access-key $SECRET_ACCESS_KEY --session-token $SESSION_TOKEN |tee -a aws-nuke.log;
                          nuke_pid=$!;
                          wait $nuke_pid;
                      - echo "Completed Nuke Process for all accounts"
                  post_build:
                    commands:
                      - cat aws-nuke.log
            """
        }
    )
    print (response)
    return response

def execute_codebuildproject(wipeaccountid):
    client = boto3.client('codebuild')
    response = client.start_build(
        projectName='AccountWipe_'+wipeaccountid+"",
        environmentVariablesOverride=[
            {
                'name': 'WipeAccountId',
                'type': 'PLAINTEXT',
                'value': wipeaccountid
            },
        ],
    )
    print (response)
    return response

def main(event,context):
    print(event)
    client = get_client('codebuild')
    wipeaccountid = os.environ['wipeaccountid']
    # Master account number and IAM wipe execution role names
    accountid="111111111111"
    accountrole="name_of_IAMrole_in_account_with_nuke/superuser_privileges"
    
    print("accountname: {}".format(wipeaccountid))
    
    if (event['RequestType'] == 'Create'):
        selfinvoke(event,'Wait')

        # Get the root account ID.
        org_client = boto3.client('organizations')
        root_id = event['ServiceToken'].split(':')[4]
        print("Root Account ID = "+root_id)

        # Create new account local AWS Nuke CodeBuild execution role.
        print("--- Creating AWS Nuke Codebuild project special execution role ---")
        newrole = "accountwiper_codebuildrole_"+wipeaccountid+""
        newtrustpolicy = json.dumps (
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "codebuild.amazonaws.com"
                            },
                            "Action": "sts:AssumeRole"
                            }
                        ]
                    }
        )
        newrolepolicy = json.dumps (
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowFullS3",
                                "Effect": "Allow",
                                "Action": [
                                    "s3:*"
                                ],
                                "Resource": "*"
                            },
                            {
                                "Sid": "AWSNukeLogPolicy",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": [
                                    "arn:aws:logs:us-west-2:"+root_id+":log-group:accountwiper_"+wipeaccountid+"",
                                    "arn:aws:logs:us-west-2:"+root_id+":log-group:accountwiper_"+wipeaccountid+":*"
                                ]
                            },
                            {
                                "Sid": "ECRPullandAuthPolicy",
                                "Effect": "Allow",
                                "Action": [
                                    "ecr:GetAuthorizationToken",
                                    "ecr:BatchCheckLayerAvailability",
                                    "ecr:GetDownloadUrlForLayer",
                                    "ecr:BatchGetImage"
                                ],
                                "Resource": [
                                    "*"
                                ]
                            },
                            {
                                "Sid": "AssumeAWSNukePolicy",
                                "Effect": "Allow",
                                "Action": [
                                    "sts:AssumeRole"
                                ],
                                "Resource": "arn:aws:iam::"+wipeaccountid+":role/OrganizationAccountAccessRole"
                            }
                        ]
                    }
        )
        # delete any pre-existing role with specific account wiper name
        try:
            iam = boto3.resource('iam')
            role = iam.Role("accountwiper_codebuildrole_"+wipeaccountid+"")
            role_policy = iam.RolePolicy("accountwiper_codebuildrole_"+wipeaccountid+"","accountwiper_codebuildrole_"+wipeaccountid+"")
            response = role_policy.delete()
            response = role.delete()
            print ("A Pre-existing account wiper IAM role for the account was found and deleted.")
        except botocore.exceptions.ClientError as e:
            print("Error deleting pre-existing account wiper IAM role{} : {}".format("accountwiper_codebuildrole_"+wipeaccountid+"",e))

        #Create require account wiper role
        newrole_arn = create_newrole(newrole,newrolepolicy,newtrustpolicy)
        print(newrole_arn)
        
        # Delete any existing AWS Nuke Wipe Project that exists
        try:
            client = boto3.client('codebuild')
            response = client.delete_project(name = "AccountWipe_" + wipeaccountid +"")
            print ("A Pre-existing account wiper Codebuild Project for the account was found and deleted.")
        except botocore.exceptions.ClientError as e:
            print("A Pre-existing account wiper Codebuild Project was not found: {}".format(e))
        # Create CodeBuild AWS Nuke Account Wipe Project 
        time.sleep(10)
        response = create_codebuildproject(wipeaccountid, root_id)

        # Execute the AWS Nuke Code Build Project
        response = execute_codebuildproject(wipeaccountid)

        # Tell Cloudformation custom lambda function successfully deployed
        send(event, context, 'SUCCESS', {'Status': 'SUCCESS'},"accountwiper_codebuildrole_"+wipeaccountid+"")
        return 'SUCCESS'
    
    elif event['RequestType'] == 'Delete':
        # Tell Cloudformation custom lambda function successfully deployed
        send(event, context, 'SUCCESS', {'Status': 'SUCCESS'},"accountwiper_codebuildrole_"+wipeaccountid+"")
        return 'SUCCESS'
        
