# 7. Leaked AWS Key to RDS via Lambda Abuse

## 🗺️ Overview
This scenario demonstrates how a leaked AWS access key with limited Lambda permissions can be escalated into a full database compromise. Starting with credentials that allow only Lambda list and describe actions, the attacker enumerates functions and extracts environment variables, uncovering a second AWS key embedded within one of the functions. This credential carries RDS manipulation privileges, enabling the attacker to enumerate databases, create a backup and restore it as a publicly accessible instance. They then change the database password and connect directly to the exposed RDS database, gaining persistent access to sensitive information. The exercise highlights the dangers of poor secret management, overly permissive IAM roles and insecure RDS configurations that allow attackers to chain weak access into full database compromise.

&nbsp;

## 🧩 Required Resources

**Networking**
- 1 × VPC - Private and public subnets  
- Security Group - Allows RDS connectivity  

**Compute**
- Lambda function - Stores AWS keys in environment variables  

**Serverless**
- Lambda - Permissions to list/describe functions  

**Storage / Database**
- RDS instance - Stores sensitive data, manipulated by attacker  

**IAM / Identities & Access**
- Leaked AWS key - Lambda list/describe permissions  
- IAM role for Lambda - Contains AWS key in environment variables  
- Secondary IAM role - RDS manipulation permissions  

&nbsp;

## 🎯 Scenario Goals
Simulate abuse of leaked AWS credentials, escalation from Lambda to RDS, and impact of unauthorized database access and manipulation.  

&nbsp;

## 🖼️ Diagram
![Diagram](./diagram.png)

&nbsp;

## 🗡️ Attack Walkthrough
- **Initial Access** - Attacker obtains AWS key with Lambda permissions.  
- **Enumeration** - Use the key to list and describe Lambda functions.  
- **Credential Discovery** - Extract environment variables to reveal a second AWS key.  
- **Privilege Escalation** - Second key grants RDS manipulation permissions.  
- **Database Reconnaissance** - List available RDS databases.  
- **Exposure** - Create backup, restore as public instance, and change password.  
- **Access** - Connect to the exposed RDS database.  

&nbsp;

## 📈 Expected Results
**Successful Completion**
- RDS instance exposed and accessed with modified credentials.  

**Detection Opportunities**
- ?

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
