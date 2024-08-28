import argparse
from googleapiclient import discovery
from googleapiclient.errors import HttpError

def build_service(api_name, api_version):
    return discovery.build(api_name, api_version)

def get_all_regions(project_id):
    compute = build_service('compute', 'v1')
    try:
        regions_response = compute.regions().list(project=project_id).execute()
        regions = [region['name'] for region in regions_response.get('items', [])]
        return regions
    except HttpError as e:
        print(f"Error listing regions: {e}")
        return []

def get_all_zones(project_id):
    compute = build_service('compute', 'v1')
    try:
        zones_response = compute.zones().list(project=project_id).execute()
        zones = [zone['name'] for zone in zones_response.get('items', [])]
        return zones
    except HttpError as e:
        print(f"Error listing zones: {e}")
        return []

def count_vpc_networks(project_id):
    compute = build_service('compute', 'v1')
    try:
        networks = compute.networks().list(project=project_id).execute()
        return len(networks.get('items', []))
    except HttpError as e:
        print(f"Error listing VPC networks: {e}")
        return 0

def count_vpc_subnets(project_id):
    compute = build_service('compute', 'v1')
    try:
        subnets = compute.subnetworks().aggregatedList(project=project_id).execute()
        return sum(len(subnet['subnetworks']) for subnet in subnets.get('items', {}).values() if 'subnetworks' in subnet)
    except HttpError as e:
        print(f"Error listing VPC subnets: {e}")
        return 0

def count_vpc_firewall_rules(project_id):
    compute = build_service('compute', 'v1')
    try:
        firewalls = compute.firewalls().list(project=project_id).execute()
        return len(firewalls.get('items', []))
    except HttpError as e:
        print(f"Error listing VPC firewall rules: {e}")
        return 0

def count_compute_instances(project_id, zone):
    compute = build_service('compute', 'v1')
    try:
        instances = compute.instances().list(project=project_id, zone=zone).execute()
        return len(instances.get('items', []))
    except HttpError as e:
        print(f"Error listing Compute instances in {zone}: {e}")
        return 0

def count_compute_disks(project_id, zone):
    compute = build_service('compute', 'v1')
    try:
        disks = compute.disks().list(project=project_id, zone=zone).execute()
        return len(disks.get('items', []))
    except HttpError as e:
        print(f"Error listing Compute disks in {zone}: {e}")
        return 0

def count_kms_keys(project_id):
    kms = build_service('cloudkms', 'v1')
    try:
        global_keys = 0
        global_key_rings = kms.projects().locations().keyRings().list(parent=f"projects/{project_id}/locations/global").execute()
        for key_ring in global_key_rings.get('keyRings', []):
            keys = kms.projects().locations().keyRings().cryptoKeys().list(parent=key_ring['name']).execute()
            global_keys += len(keys.get('cryptoKeys', []))
        
        regional_keys = 0
        regions = get_all_regions(project_id)
        for region in regions:
            regional_key_rings = kms.projects().locations().keyRings().list(parent=f"projects/{project_id}/locations/{region}").execute()
            for key_ring in regional_key_rings.get('keyRings', []):
                keys = kms.projects().locations().keyRings().cryptoKeys().list(parent=key_ring['name']).execute()
                regional_keys += len(keys.get('cryptoKeys', []))
        
        return {'global': global_keys, 'regional': regional_keys}
    except HttpError as e:
        print(f"Error listing KMS keys: {e}")
        return {'global': 0, 'regional': 0}

def count_sql_instances(project_id):
    sql = build_service('sqladmin', 'v1')
    try:
        instances = sql.instances().list(project=project_id).execute()
        return len(instances.get('items', []))
    except HttpError as e:
        print(f"Error listing Cloud SQL instances: {e}")
        return 0

def count_buckets(project_id):
    storage = build_service('storage', 'v1')
    try:
        buckets = storage.buckets().list(project=project_id).execute()
        return len(buckets.get('items', []))
    except HttpError as e:
        print(f"Error listing Cloud Storage buckets: {e}")
        return 0

def count_load_balancers(project_id):
    compute = build_service('compute', 'v1')
    try:
        https_proxies = compute.targetHttpsProxies().list(project=project_id).execute()
        return len(https_proxies.get('items', []))
    except HttpError as e:
        print(f"Error listing HTTPS load balancers: {e}")
        return 0

def count_iam_roles(project_id):
    iam = build_service('iam', 'v1')
    try:
        roles = iam.roles().list(parent=f'projects/{project_id}').execute()
        return len(roles.get('roles', []))
    except HttpError as e:
        print(f"Error listing IAM roles: {e}")
        return 0

def count_kubernetes_clusters(project_id, region):
    container = build_service('container', 'v1')
    try:
        clusters = container.projects().locations().clusters().list(parent=f"projects/{project_id}/locations/{region}").execute()
        return len(clusters.get('clusters', []))
    except HttpError as e:
        print(f"Error listing Kubernetes clusters in {region}: {e}")
        return 0

def count_kubernetes_nodes(project_id, region):
    container = build_service('container', 'v1')
    try:
        clusters = container.projects().locations().clusters().list(parent=f"projects/{project_id}/locations/{region}").execute()
        return sum(len(cluster.get('nodePools', [])) for cluster in clusters.get('clusters', []))
    except HttpError as e:
        print(f"Error listing Kubernetes nodes in {region}: {e}")
        return 0

def count_dns_zones(project_id):
    dns = build_service('dns', 'v1')
    try:
        zones = dns.managedZones().list(project=project_id).execute()
        return len(zones.get('managedZones', []))
    except HttpError as e:
        print(f"Error listing DNS zones: {e}")
        return 0

def count_logging_sinks(project_id):
    logging = build_service('logging', 'v2')
    try:
        sinks = logging.sinks().list(parent=f"projects/{project_id}").execute()
        return len(sinks.get('sinks', []))
    except HttpError as e:
        print(f"Error listing Logging sinks: {e}")
        return 0

def count_pubsub_topics(project_id):
    pubsub = build_service('pubsub', 'v1')
    try:
        topics = pubsub.projects().topics().list(project=f'projects/{project_id}').execute()
        return len(topics.get('topics', []))
    except HttpError as e:
        print(f"Error listing Pub/Sub topics: {e}")
        return 0

def count_pubsub_subscriptions(project_id):
    pubsub = build_service('pubsub', 'v1')
    try:
        subscriptions = pubsub.projects().subscriptions().list(project=f'projects/{project_id}').execute()
        return len(subscriptions.get('subscriptions', []))
    except HttpError as e:
        print(f"Error listing Pub/Sub subscriptions: {e}")
        return 0

def count_dataflow_jobs(project_id, region):
    dataflow = build_service('dataflow', 'v1b3')
    try:
        jobs = dataflow.projects().locations().jobs().list(projectId=project_id, location=region).execute()
        return len(jobs.get('jobs', []))
    except HttpError as e:
        print(f"Error listing Dataflow jobs in {region}: {e}")
        return 0

def count_cloud_functions(project_id):
    functions = build_service('cloudfunctions', 'v1')
    try:
        functions_response = functions.projects().locations().functions().list(parent=f"projects/{project_id}/locations/-").execute()
        return len(functions_response.get('functions', []))
    except HttpError as e:
        print(f"Error listing Cloud Functions: {e}")
        return 0

def main():
    parser = argparse.ArgumentParser(description='List and count GCP resources.')
    parser.add_argument('project_id', help='GCP Project ID')
    args = parser.parse_args()
    project_id = args.project_id

    regions = get_all_regions(project_id)
    zones = get_all_zones(project_id)

    global_counts = {
        'VPC Networks': count_vpc_networks(project_id),
        'VPC Subnets': count_vpc_subnets(project_id),
        'VPC Firewall Rules': count_vpc_firewall_rules(project_id),
        'SQL Instances': count_sql_instances(project_id),
        'Buckets': count_buckets(project_id),
        'Load Balancers': count_load_balancers(project_id),
        'IAM Roles': count_iam_roles(project_id),
        'DNS Zones': count_dns_zones(project_id),
        'Logging Sinks': count_logging_sinks(project_id),
        'Pub/Sub Topics': count_pubsub_topics(project_id),
        'Pub/Sub Subscriptions': count_pubsub_subscriptions(project_id),
        'Cloud Functions': count_cloud_functions(project_id)
    }

    regional_counts = {
        'Compute Instances': sum(count_compute_instances(project_id, zone) for zone in zones),
        'Compute Disks': sum(count_compute_disks(project_id, zone) for zone in zones),
        'Kubernetes Clusters': sum(count_kubernetes_clusters(project_id, region) for region in regions),
        'Kubernetes Nodes': sum(count_kubernetes_nodes(project_id, region) for region in regions),
        'Dataflow Jobs': sum(count_dataflow_jobs(project_id, region) for region in regions)
    }

    kms_keys = count_kms_keys(project_id)

    print("Global Resource Counts:")
    for resource, count in global_counts.items():
        print(f"{resource}: {count}")

    print("\nRegional Resource Counts:")
    for resource, count in regional_counts.items():
        print(f"{resource}: {count}")

    print(f"\nKMS Keys (Global): {kms_keys['global']}")
    print(f"KMS Keys (Regional): {kms_keys['regional']}")

if __name__ == "__main__":
    main()
