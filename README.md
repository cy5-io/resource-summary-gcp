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
    git clone https://github.com/cy5-io/resource-summary-gcp.git
    cd resource-summary-gcp
    ```

2. Install the required dependencies:
    ```bash
    pip install --upgrade google-api-python-client google-auth google-auth-httplib2 google-auth-oauthlib
    ```

### Execution:

Run the script with your GCP project ID:
```bash
python gcp-resource-count-all-region.py <your-project-id>
```

### Sample output

```bash
Global Resource Counts:
VPC Networks: 5
VPC Subnets: 10
VPC Firewall Rules: 12
Cloud SQL Instances: 3
Cloud Storage Buckets: 15
Load Balancers: 2
IAM Roles: 10
DNS Zones: 1
Logging Sinks: 2
Pub/Sub Topics: 5
Pub/Sub Subscriptions: 4
Cloud Functions: 7

Regional Resource Counts:
Compute Instances: 24
Compute Disks: 30
Kubernetes Clusters: 3
Kubernetes Nodes: 30
Dataflow Jobs: 2

KMS Keys (Global): 10
KMS Keys (Regional): 15
```
