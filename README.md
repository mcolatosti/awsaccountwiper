# account-wiper
The account-wiper project is a special highly privileged and dangerous service to delete all content and configuration and to restore an AWS account to its initial creation state.
The account-wiper process is a special-case IaC (Infrastructure as Code) scenario that needs to be performed only once per account reset.
This task is performed OUTSIDE of Terraform and from the master account where these goals can be accomplished in a simpler, stateless manner and can leverage the existing AWS Service Catalog as the user interface.
- Special Note: The account-wiper project is NOT a Terraform-based IaC project, and therefore has different deployment requirements and procedures!

The Account Wiper solution is principly achieved by an Open Source project called AWS-Nuke, a command line utility that iterates through an AWS account and destroys all resources and data that it has been intructed to delete.
The solution achieves this objective by executing the following actions:
- Launching a lambda function from the AWS Service Catalog "AWS Wiper" with the service catalog product supplied inputs.
- Since an AWS-Nuke run job can and will likely run longer than an AWS lambda job is permitted to execute, this lambda function serves the following functions:
  1. Cleaning up account wiper objects from any prior run for a given account in the master account.
  2. Creating a Codebuild project that ultimately creates and launches a AWS Linux EC2 docker image with required code and software.
  3. Launching the Codebuild project to affect actual account wipe functionality.

## Features Currently present:
- Currently deployed as a service catalog product.
- Centralized AWS-Nuke configuration file that can control scope of wipes, objects and even AWS accounts exempt from destruction.  These policies are then maintained external to code where desired.
- Detailed product and codebuild AWS-Nuke wiping logs in standard persistent cloudwatch log streams.

## Features to be coded or configured:
- Clean up of Terraform state file and associated documents for a given account (across all projects, and likely an "archive" function so data is available for historical or recovery purposes)
- Provide visibility to process, ideally a nice dashboard / summary type result at completion.
- Perhaps some additional sanity checks outside of tool to verify account has a high probability of being "clean" and free of artifacts that could impair future account use and deployments.
- Security objects and roles to permit delegating this application to others.

## Special Project Information & Requirements
- A special master organization account AWS S3 iac bucket must exist for the storage of this project's configuration files.  It is recommended to use the same IAC specialized application bucket as used by the Account Creation product.
- "aws-nuke-config.yaml" AWSNuke file must reside in the S3 bucket and folder created above.
- "accountwiper-iac.json" contains the AWS Service catalog product code.
- "AccountWiperLambda.py" is the lambda python code that defines and coordinates all the account wiper functions.


## Special Project Information & Requirements
- A special master organization account AWS S3 iac bucket must exist for the storage of this project's configuration files.
- The AccountWiperLambda.py python script must be packaged as a zip file with a file name of "AccountWiperLambda.zip" and stored in the special master S3 bucket. As the name suggests it is a lambda function launched in the master account and provides all the account wiping code and logic and becomes the package used by the AWS Service Catlog specification.  The "aws-nuke-config.yaml" file is a configuration and control file that controls the behaviour of the AWS-Nuke process.
- The accountwiper-iac.json file defines the "Account Wiper" AWS service catalog product to be published in the master account, ultimately this provides the user interface to wipe existing accounts.
- The aws-nuke-config.yaml file is stored in the special IaC bucket and permits the customization of the AWS-Nuke processes, including whitelisting or blacklisting accounts that are permitted to participate as well as excluding resources from being wiped from an account.  For instance in an environment using Terraform to deploy resources, you may want to ensure terraform deployment roles and role policies are not erased and continue to be present to redeploy services via a Terraform CI/CD pipeline to the wiped account for the account's new purpose.
- At present S3 names and paths, cloudwatch logging, etc. values are hardcoded in the program files and may need to be modified to reflect your environment manually.

## Other Notes
This project is considered largely a POC and is primarily should be used as a potential framework and concept for achieving AWS Account reuse in an automated way.  Hopefully someone finds the concept and details here useful for their purposes.
This project is intended to be part of a larger more mature Infrastructure as Code (IaC) project that spins up accounts and performs "bootstrapping" functions needed by a CI/CD pipeline used to further configure and deploy networking and applications via Terraform.  This "Account-Bootstrapper" project which is basically a customized replacement for AWS Landing Zones for use with a very specific CI/CD Terraform pipeline strategy, may be published at a later date.
