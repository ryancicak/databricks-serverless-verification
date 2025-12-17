# Databricks Serverless S3 Access Debugger

This tool verifies that Databricks Serverless jobs can access a specific S3 bucket. It automates the setup of Unity Catalog (Storage Credential and External Location) and runs a test job to confirm read/write permissions.

## Overview

Databricks Serverless compute cannot access S3 directly using instance profiles or keys. It requires a Unity Catalog External Location to bridge the connection. This project provides a script to:

1.  Create a test S3 bucket (using your local AWS credentials).
2.  Update an IAM Role with the necessary S3 permissions.
3.  Create the Unity Catalog Storage Credential and External Location.
4.  Submit a Serverless Job that writes to and reads from the bucket.

## Prerequisites

*   **Databricks Workspace**: You need a workspace with Unity Catalog enabled.
*   **Databricks Authentication**: Either a Personal Access Token (PAT) or OAuth credentials (Client ID/Secret).
*   **AWS Credentials**: Access keys capable of creating S3 buckets and updating IAM roles.
*   **Python 3**: Installed on your local machine.
*   **Databricks SDK**: `pip install databricks-sdk`

## Usage

1.  Clone this repository.
2.  Make the script executable:
    ```bash
    chmod +x verify_serverless_s3.sh
    ```
3.  Run the script:
    ```bash
    ./verify_serverless_s3.sh
    ```

The script will guide you through the process. It will ask for a name for a new test bucket and then attempt to auto-discover your Databricks user and IAM role settings.

## What It Does

The script performs the following actions:

1.  **Discovery**: Finds your Databricks username and an existing IAM role used by Unity Catalog.
2.  **AWS Setup**: Creates a new S3 bucket and attaches an inline policy to your IAM role granting access to that bucket.
3.  **Unity Catalog Configuration**:
    *   Creates a `Storage Credential` linking to your IAM Role.
    *   Creates an `External Location` pointing to the new S3 bucket.
    *   Grants `READ FILES` and `WRITE FILES` permissions to your user.
4.  **Verification**: Uploads a Python notebook and submits it as a Databricks Job using Serverless compute. The job writes a file to S3 and verifies it can read it back.

## Troubleshooting

If the verification fails:

*   **403 Forbidden**: This usually means the IAM Role does not have `s3:GetObject`, `s3:PutObject`, or `s3:ListBucket` permissions for the specific bucket. The script attempts to fix this automatically.
*   **Serverless not available**: Ensure your workspace supports Serverless compute and it is enabled.

## Cleanup

At the end of the run, the script will offer to delete the test S3 bucket. The Unity Catalog objects (Credential and External Location) are left in place but can be manually deleted from the Databricks UI if desired.

