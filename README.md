# gcp-resource-summary

This command-line utility generates a summary of resources across a GCP project.

It is a Python script that counts resources across different regions and displays them on the command line. The script takes the GCP project ID as input and displays the resource count for various resources, both global and regional. 

## Resources Summarized:

- **KMS Keys** (Global and Regional)
- **VPC Networks**
- **VPC Subnets**
- **VPC Firewall Rules**
- **Compute Instances**
- **Compute Disks**
- **Cloud SQL Instances**
- **Cloud Storage Buckets**
- **Load Balancers**
- **IAM Roles**
- **Kubernetes Clusters**
- **Kubernetes Nodes**
- **DNS Zones**
- **Logging Sinks**
- **Pub/Sub Topics**
- **Pub/Sub Subscriptions**
- **Dataflow Jobs**
- **Cloud Functions**

## Usage (supports Python 3.x):

### Installation:

1. Clone the repository:
    ```bash
    git clone https://github.com/your-repo/gcp-resource-summary.git
    cd gcp-resource-summary
    ```

2. Install the required dependencies:
    ```bash
    pip install --upgrade google-api-python-client google-auth google-auth-httplib2 google-auth-oauthlib
    ```

### Execution:

Run the script with your GCP project ID:
```bash
python resource_summary.py <your-project-id>
```
