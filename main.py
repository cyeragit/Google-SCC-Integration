import requests
import random
import string
import time
import re
from google.cloud import securitycenter_v2
from google.cloud import secretmanager_v1 as secretmanager
from google.protobuf.timestamp_pb2 import Timestamp
import os
from google.auth import default

# ✅ Initialize Secret Manager Client
SECRET_MANAGER_CLIENT = secretmanager.SecretManagerServiceClient()

if "GOOGLE_APPLICATION_CREDENTIALS" not in os.environ:
    print("⚠️ Warning: GOOGLE_APPLICATION_CREDENTIALS is not set. Using default credentials.")
    credentials, project_id = default()
else:
    print(f"✅ Using credentials from: {os.getenv('GOOGLE_APPLICATION_CREDENTIALS')}")
    credentials, project_id = default()

def get_secret(secret_name):
    """
    Retrieves a secret value from Google Secret Manager.
    Dynamically determines the current GCP project ID to avoid hardcoding.
    """
    try:
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT")  
        if not project_id:
            credentials, project_id = default()

        if not project_id:  
            print("❌ Error: PROJECT_ID is empty or not retrieved correctly from Secret Manager.")
            exit(1)

        print(f"✅ Retrieved PROJECT_ID: {project_id}")

        secret_path = f"projects/{project_id}/secrets/{secret_name}/versions/latest"

        response = SECRET_MANAGER_CLIENT.access_secret_version(request={"name": secret_path})

        return response.payload.data.decode("UTF-8").strip()

    except Exception as e:
        print(f"❌ Error retrieving secret `{secret_name}`: {e}")
        exit(1)

# ✅ Retrieve secrets
CLIENT_ID = get_secret("CLIENT_ID")
CLIENT_SECRET = get_secret("CLIENT_SECRET")
PROJECT_ID = get_secret("PROJECT_ID")

# ✅ Cyera API Configuration
BASE_URL = "https://api.cyera.io"
AUTH_ENDPOINT = "/v1/login"
ISSUES_ENDPOINT = "/v3/issues"
DATASTORES_ENDPOINT = "/v2/datastores"
LIMIT = 100

def get_jwt_token():
    url = f"{BASE_URL}{AUTH_ENDPOINT}"
    payload = {"clientId": CLIENT_ID, "secret": CLIENT_SECRET}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        return response.json()["jwt"]
    else:
        print(f"❌ Authentication failed: {response.text}")
        exit(1)

def get_all_issues(jwt_token):
    offset = 0
    all_issues = []
    headers = {"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"}
    
    while True:
        url = f"{BASE_URL}{ISSUES_ENDPOINT}"
        params = {"limit": LIMIT, "offset": offset}
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            issues = data.get("results", [])
            if not issues:
                break

            all_issues.extend(issues)
            offset += LIMIT
        else:
            print(f"❌ Failed to fetch issues: {response.text}")
            exit(1)

    return all_issues

##########

def get_datastore(token, datastore_uid):
    """Fetches datastore details for a given UID."""
    datastore_url = f"{BASE_URL}{DATASTORES_ENDPOINT}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(datastore_url, headers=headers, params={"uid": datastore_uid, "limit": 1, "offset": 0})

    if response.status_code == 200:
        results = response.json().get("results", [])
        return results[0] if results else None
    else:
        print(f"Error fetching datastore {datastore_uid}: {response.status_code}")
        return None

###############



def authenticate_scc():
    return securitycenter_v2.SecurityCenterClient()

def get_organization_id(client, project_id):
    from google.cloud import resourcemanager_v3
    resource_client = resourcemanager_v3.ProjectsClient()
    project_path = f"projects/{project_id}"
    project = resource_client.get_project(name=project_path)
    return project.parent.split("/")[-1] if project.parent.startswith("organizations/") else None

def get_or_create_scc_source(client, organization_id):
    parent = f"organizations/{organization_id}"
    for source in client.list_sources(request={"parent": parent}):
        if source.display_name == "Cyera Issues":
            return source.name.split("/")[-1]

    new_source = securitycenter_v2.Source(
        display_name="Cyera Issues",
        description="Findings imported from Cyera."
    )
    response = client.create_source(request={"parent": parent, "source": new_source})
    return response.name.split("/")[-1]

def map_severity(cyera_severity):
    severity_map = {
        "CRITICAL": securitycenter_v2.Finding.Severity.CRITICAL,
        "HIGH": securitycenter_v2.Finding.Severity.HIGH,
        "MEDIUM": securitycenter_v2.Finding.Severity.MEDIUM,
        "LOW": securitycenter_v2.Finding.Severity.LOW
    }
    return severity_map.get(cyera_severity.upper(), securitycenter_v2.Finding.Severity.LOW)

def generate_valid_finding_id(issue_uid):
    sanitized_id = re.sub(r'[^a-zA-Z0-9]', '', issue_uid)
    return sanitized_id[:32] if sanitized_id else ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))




##################################################################################################################
def create_or_update_finding(client, organization_id, source_id, issue, datastore):
    """Creates or updates a finding in SCC with Cyera issue and datastore properties."""
    parent = f"organizations/{organization_id}/sources/{source_id}"
    finding_id = generate_valid_finding_id(issue.get("uid", ""))
    event_time = Timestamp()
    event_time.GetCurrentTime()
    severity = map_severity(issue.get("severity", "LOW"))
    
    # ✅ Map Cyera Issue Datastore to SCC Resource ID
    resource_name = f"//cloudresourcemanager.googleapis.com/projects/{project_id}/datastores/{issue.get('datastoreUid', 'unknown')}"

    # ✅ Determine Finding State (Always ACTIVE unless explicitly set otherwise)
    finding_state = securitycenter_v2.Finding.State.ACTIVE

    # ✅ Prepare Finding Properties
    finding_properties = {
        "state": finding_state,  # ✅ Ensure state is set to ACTIVE
        "category": issue.get("name", "Uncategorized Issue"),
        "severity": severity,
        "event_time": event_time,
        "resource_name": resource_name,
        "description": issue.get("risk", {}).get("description", "No description available"),
        "source_properties": {
            "cyera_datastore_id": issue.get("datastoreUid", "unknown"),
            "cyera_datastore_name": datastore.get("name", "Unknown") if datastore else "Unknown",
            "cyera_datastore_provider": datastore.get("provider", "Unknown") if datastore else "Unknown",
            "cyera_datastore_type": datastore.get("type", "Unknown") if datastore else "Unknown",
            "cyera_datastore_sensitivity": datastore.get("sensitivity", "Unknown") if datastore else "Unknown",
        }
    }

    # ✅ Check if Finding Exists
    existing_finding = next(
        (f.finding for f in client.list_findings(request={"parent": parent}) if f.finding.name.endswith(finding_id)),
        None
    )

    if existing_finding:
        print(f"🔄 Updating existing finding: {existing_finding.name}")
        updated_finding = securitycenter_v2.Finding(name=existing_finding.name, **finding_properties)
        client.update_finding(request=securitycenter_v2.UpdateFindingRequest(
            finding=updated_finding,
            update_mask={"paths": ["state", "severity", "event_time", "description", "source_properties"]}
        ))
        print(f"✅ Finding Updated: {existing_finding.name} (Severity: {severity.name})")
    else:
        print(f"🆕 Creating new finding: {finding_id}")
        new_finding = securitycenter_v2.Finding(**finding_properties)
        response = client.create_finding(request=securitycenter_v2.CreateFindingRequest(
            parent=parent, finding_id=finding_id, finding=new_finding
        ))
        print(f"✅ New Finding Created: {response.name}")


def cloud_function_entry(data, context):
    """
    Event-Triggered Google Cloud Function entry point.
    `data` contains event payload, `context` contains metadata.
    """
    try:
        print(f"✅ Received Event ID: {context.event_id}")
        print(f"✅ Event Type: {context.event_type}")

        jwt_token = get_jwt_token()
        issues = get_all_issues(jwt_token)
        scc_client = authenticate_scc()
        organization_id = get_organization_id(scc_client, PROJECT_ID)

        if not organization_id:
            return "❌ Could not retrieve organization ID.", 500

        source_id = get_or_create_scc_source(scc_client, organization_id)

        for issue in issues:
            datastore_uid = issue.get("datastoreUid")
            datastore = get_datastore(jwt_token, datastore_uid) if datastore_uid else None
            create_or_update_finding(scc_client, organization_id, source_id, issue, datastore)
            
        print(f"✅ Successfully processed {len(issues)} findings in SCC.")
    except Exception as e:
        print(f"❌ Error processing event: {str(e)}")

