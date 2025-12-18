#!/bin/bash

# Databricks & AWS S3 Permission Verification Script (Automated)
# Usage: ./verify_serverless_s3.sh
# 
# What it does:
# 1. Asks for a Test Bucket Name (and auth if missing).
# 2. Auto-detects your Databricks User.
# 3. Auto-detects an existing IAM Role from your Databricks Storage Credentials.
# 4. Creates the bucket, updates the IAM Role, configures UC, and runs a Serverless Test.

set -e
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}      Databricks Serverless S3 Access Verification Tool      ${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

# --- 1. Authentication & Inputs ---

# Check/Prompt for Databricks Credentials
if [ -z "$DATABRICKS_HOST" ]; then
    read -p "Enter Databricks Workspace URL: " DATABRICKS_HOST
    export DATABRICKS_HOST
fi

if [ -z "$DATABRICKS_TOKEN" ] && [ -z "$DATABRICKS_CLIENT_ID" ]; then
    echo "Auth needed."
    echo "1) Personal Access Token (PAT)"
    echo "2) OAuth (Client ID & Secret)"
    read -p "Choice [1/2]: " AUTH_CHOICE
    if [ "$AUTH_CHOICE" == "1" ]; then
        read -s -p "Token: " DATABRICKS_TOKEN
        echo ""
        export DATABRICKS_TOKEN
    else
        read -p "Client ID: " DATABRICKS_CLIENT_ID
        read -s -p "Client Secret: " DATABRICKS_CLIENT_SECRET
        echo ""
        export DATABRICKS_CLIENT_ID
        export DATABRICKS_CLIENT_SECRET
        export DATABRICKS_AUTH_TYPE=oauth-m2m
    fi
fi

# Check/Prompt for AWS Credentials
if [ -z "$AWS_PROFILE" ] && [ -z "$AWS_ACCESS_KEY_ID" ]; then
    echo ""
    echo -e "${BLUE}--- AWS Setup ---${NC}"
    echo "Need AWS credentials to create the bucket and update the IAM role."
    read -p "Use AWS Profile? (Leave empty for manual keys): " AWS_PROFILE_INPUT
    if [ ! -z "$AWS_PROFILE_INPUT" ]; then
        export AWS_PROFILE=$AWS_PROFILE_INPUT
    else
        read -p "AWS Access Key ID: " AWS_ACCESS_KEY_ID
        read -s -p "AWS Secret Access Key: " AWS_SECRET_ACCESS_KEY
        echo ""
        read -p "AWS Region (e.g. us-east-1): " AWS_DEFAULT_REGION
        export AWS_ACCESS_KEY_ID
        export AWS_SECRET_ACCESS_KEY
        export AWS_DEFAULT_REGION
    fi
fi

# THE ONLY REQUIRED INPUT
echo ""
read -p "Enter a name for the NEW Test Bucket: " TEST_BUCKET_NAME

# --- 2. Auto-Discovery ---
echo ""
echo -e "${BLUE}--- Auto-Detecting Configuration... ---${NC}"

# We use a python script to discover the user and role
cat <<EOF > discover_config.py
import os
import sys
from databricks.sdk import WorkspaceClient

try:
    w = WorkspaceClient()
    
    # 1. Get Principal
    me = w.current_user.me()
    print(f"PRINCIPAL={me.user_name}")
    
    # 2. Get IAM Role from existing credentials
    creds = list(w.storage_credentials.list())
    found_arn = ""
    for c in creds:
        if c.aws_iam_role:
            found_arn = c.aws_iam_role.role_arn
            break # Just take the first one
            
    if not found_arn:
        print("ERROR: No Storage Credentials with IAM Roles found in Databricks!")
        sys.exit(1)
        
    print(f"IAM_ROLE_ARN={found_arn}")
    
    # Extract Role Name from ARN (arn:aws:iam::account:role/role-name)
    role_name = found_arn.split("/")[-1]
    print(f"IAM_ROLE_NAME={role_name}")

except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
EOF

# Run discovery and source the output
python3 discover_config.py > config.env
if [ $? -ne 0 ]; then
    cat config.env
    echo -e "${RED}Discovery failed.${NC}"
    rm discover_config.py config.env
    exit 1
fi

source config.env
rm discover_config.py config.env

echo "Detected User: $PRINCIPAL"
echo "Detected Role: $IAM_ROLE_NAME ($IAM_ROLE_ARN)"

# --- 3. Execution ---

echo ""
echo -e "${GREEN}1. Creating Bucket: $TEST_BUCKET_NAME...${NC}"
if aws s3 ls "s3://$TEST_BUCKET_NAME" 2>&1 | grep -q 'NoSuchBucket'; then
    aws s3 mb "s3://$TEST_BUCKET_NAME"
else
    echo "Bucket exists."
fi

echo ""
echo -e "${GREEN}2. Updating IAM Role Permissions...${NC}"
# Inline policy for the specific bucket
POLICY_JSON=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::$TEST_BUCKET_NAME",
                "arn:aws:s3:::$TEST_BUCKET_NAME/*"
            ]
        }
    ]
}
EOF
)
aws iam put-role-policy --role-name "$IAM_ROLE_NAME" --policy-name "DatabricksTestAccess-${TEST_BUCKET_NAME}" --policy-document "$POLICY_JSON"
echo "Policy attached to $IAM_ROLE_NAME."

echo ""
echo -e "${GREEN}3. Setting up Unity Catalog & Running Job...${NC}"

cat <<EOF > run_test.py
import os
import base64
import time
from databricks.sdk import WorkspaceClient
from databricks.sdk.service import catalog, jobs, workspace

w = WorkspaceClient()

# Config
bucket_name = "${TEST_BUCKET_NAME}"
iam_role_arn = "${IAM_ROLE_ARN}"
principal = "${PRINCIPAL}"
cred_name = f"test_cred_{bucket_name.replace('-', '_')}"
loc_name = f"test_loc_{bucket_name.replace('-', '_')}"
bucket_url = f"s3://{bucket_name}/"

# 1. Create Credential (if needed)
print(f"Creating Credential: {cred_name}")
try:
    w.storage_credentials.create(
        name=cred_name,
        aws_iam_role=catalog.AwsIamRole(role_arn=iam_role_arn)
    )
except Exception as e:
    if "already exists" in str(e): print("Credential exists.")
    else: raise e

# 2. Create Location
print(f"Creating External Location: {loc_name}")
try:
    w.external_locations.create(
        name=loc_name,
        url=bucket_url,
        credential_name=cred_name
    )
except Exception as e:
    if "already exists" in str(e): 
        print("Location exists.")
    elif "PERMISSION_DENIED" in str(e) or "User does not have CREATE EXTERNAL LOCATION" in str(e):
        print(f"\n{'-'*60}")
        print("STOP: PERMISSION ERROR")
        print(f"You do not have permission to create External Locations on this Metastore.")
        print(f"Please ask a Metastore Admin to run this SQL for you:")
        print(f"   GRANT CREATE EXTERNAL LOCATION ON METASTORE TO `{principal}`;")
        print(f"{'-'*60}\n")
        
        # Interactive Prompt to Retry
        while True:
            resp = input("Have you (or an admin) fixed the permission? Type 'retry' to try again, or 'skip' to skip creation (if it already exists): ").lower()
            if resp == 'retry':
                try:
                    w.external_locations.create(
                        name=loc_name,
                        url=bucket_url,
                        credential_name=cred_name
                    )
                    print("Successfully created External Location on retry!")
                    break
                except Exception as retry_err:
                     print(f"Retry failed: {retry_err}")
            elif resp == 'skip':
                print("Skipping External Location creation...")
                break
    else: 
        raise e

# 3. Grant Permissions
print("Granting Permissions...")
try:
    # Try SQL execution
    wh_id = None
    for wh in w.warehouses.list():
        if wh.state.value in ["RUNNING", "STOPPED"]:
            wh_id = wh.id
            break
            
    if wh_id:
        sql = f"GRANT READ FILES, WRITE FILES ON EXTERNAL LOCATION {loc_name} TO \`{principal}\`"
        w.statement_execution.execute_statement(statement=sql, warehouse_id=wh_id, wait_timeout="30s")
        print("Permissions granted via SQL.")
    else:
        print("WARNING: No SQL Warehouse found. Skipping explicit GRANT (might fail if you are not admin).")
except Exception as e:
    print(f"Grant failed (non-fatal): {e}")

# 4. Run Job
print("Submitting Serverless Job...")
notebook_content = f"""
# Databricks Notebook Source
path = "s3://{bucket_name}/serverless_test.txt"
print(f"Writing to {{path}}")
dbutils.fs.put(path, "Verified!", True)
assert dbutils.fs.head(path) == "Verified!"
print("SUCCESS")
"""

nb_path = f"/Users/{principal}/test_serverless_{bucket_name.replace('-', '_')}"
w.workspace.import_(
    path=nb_path, 
    format=workspace.ExportFormat.SOURCE, 
    language=workspace.Language.PYTHON, 
    content=base64.b64encode(notebook_content.encode()).decode(), 
    overwrite=True
)

run = w.jobs.submit(
    run_name=f"test_serverless_{bucket_name}",
    tasks=[
        jobs.SubmitTask(
            task_key="test", 
            notebook_task=jobs.NotebookTask(notebook_path=nb_path)
            # No cluster spec = Serverless
        )
    ]
).result()

print(f"Job Status: {run.state.result_state}")
print(f"Run URL: {run.run_page_url}")

# --- Network Policy Validation ---
print("\n" + "="*50)
print("   Serverless Network Policy Validation")
print("="*50)

if run.state.result_state.value == "SUCCESS":
    print(f"✅ PASS: Serverless Network Policy allows access to s3://{bucket_name}")
else:
    # Get failure reason
    msg = run.state.state_message or ""
    if run.tasks:
        for t in run.tasks:
             if t.state.state_message:
                 msg += f"\nTask {t.task_key}: {t.state.state_message}"

    if "serverless network policy" in msg.lower():
        print(f"❌ FAIL: Strict Egress Policy is blocking access.")
        print(f"   Reason: Access to {bucket_name} is denied by the attached Network Connectivity Configuration (NCC).")
        print(f"   Action: Add 's3://{bucket_name}' to the allowed egress rules in your NCC.")
    else:
        print(f"❌ FAIL: Job failed (possibly not Network Policy related).")
        print(f"   Reason: {msg}")

if run.state.result_state.value != "SUCCESS":
    exit(1)
EOF

python3 run_test.py
RES=$?
rm run_test.py

if [ $RES -eq 0 ]; then
    echo -e "${GREEN}VERIFICATION SUCCESSFUL!${NC}"
else
    echo -e "${RED}VERIFICATION FAILED!${NC}"
fi

# Cleanup
echo ""
read -p "Delete test bucket ($TEST_BUCKET_NAME)? [y/N]: " DEL
if [[ "$DEL" =~ ^[Yy]$ ]]; then
    aws s3 rb "s3://$TEST_BUCKET_NAME" --force
    echo "Bucket deleted."
fi
