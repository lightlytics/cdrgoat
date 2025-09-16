# 5. Privilege Escalation via SSRF and Lambda Abuse

## 🗺️ Overview
This scenario demonstrates how an SSRF vulnerability in a public-facing EC2 instance can be chained with overly permissive Lambda privileges to achieve full AWS account compromise. After exploiting the vulnerable web application to access the Instance Metadata Service, the attacker retrieves IAM role credentials that grant lambda:* permissions, enabling them to create, list, modify, and invoke Lambda functions. During enumeration, they identify a Lambda used for user management and infer that it has iam:Create* permissions. By attempting to generate new access keys for guessed IAM usernames, the attacker successfully creates keys for multiple accounts, one of which belongs to an administrator. With the new admin credentials, they gain persistent, full account-wide control, demonstrating the compounded risks of SSRF exploitation, misconfigured IAM roles, and over-privileged Lambda functions.

&nbsp;

## 🧩 Required Resources

**Networking**
- 1 × VPC - Single region
- Subnets - 1 private, 1 public (EC2 in public)
- Internet Gateway - attached to VPC

**Serverless**
- Lambda function - Capable of managing IAM users and keys

**IAM / Identities & Access**
- EC2 role - lambda:* (list, modify, invoke)
- Lambda execution role - Permissions to manage IAM users and keys
- Root user - Existing account with full administrative privileges

&nbsp;

## 🎯 Scenario Goals
Demonstrate how an SSRF vulnerability can lead to credential theft, abuse of over-privileged Lambda permissions, and eventual compromise of the AWS root account.

&nbsp;

## 🖼️ Diagram
![Diagram](./diagram.png)

&nbsp;

## 🗡️ Attack Walkthrough
- **Initial Access** - Exploit SSRF in the public web app to query IMDS and steal the EC2 role’s temporary credentials.
- **Abuse EC2 Role** - Use those credentials (role has lambda:*) to list and invoke Lambda functions.
- **Discovery** - Find a user-management Lambda that has iam:CreateAccessKey (or similar IAM write) permissions.
- **Privilege Escalation** - Invoke or modify that Lambda to create access keys for guessed IAM usernames (one is an admin/root).
- **Persistence/Takeover** - Use the newly created admin/root keys for persistent, full account control.

&nbsp;

## 📈 Expected Results
**Successful Completion**
- Root user receives a newly created access key, granting the attacker persistent, full account-wide administrative privileges.  

**Detection Opportunities**
- Abnormal behavior of IAM user with multiple failed requests
- Numbers of failed IAM config changes attempts by compute resource
- IAM config change by compute resource
- Adding user to group with admin privileges

&nbsp;

## 🚀 Getting Started

#### Install Dependencies
macOS
```bash
brew install terraform awscli jq
```
Linux
```bash
sudo apt update && sudo apt install -y terraform awscli jq
```

#### 🏗️ Deploy
Before deploying, download the provided Terraform configuration and attack script to the machine where you will run the attack steps.

Use the provided Terraform configuration to deploy the full lab environment.
At the end of the deployment Terraform will display output values such as the public IP address of the target instance. Save these details, you will need them to run the attack script in the next stage.

```bash
terraform init
terraform apply -auto-approve
```

#### 🎯 Attack Execution
Execute the attack script from your local terminal and use the output values provided at the end of the deployment as input parameters.

```bash
chmod +x attack.sh
./attack.sh
```

#### 🧹 Clean Up
When you are finished, destroy all resources to avoid ongoing costs. This will tear down the entire lab environment including all compute, networking, and IAM components created during deployment.

Use the following command for a full cleanup

```bash
terraform destroy -auto-approve
```
