import requests
import sys

OWNER = "your-username"
REPO = "your-repo"
WORKFLOW = "zap-dast.yml"
TOKEN = "YOUR_GITHUB_TOKEN"  # store safely

if len(sys.argv) < 2:
    print("Usage: python zap-dast.py <target_url>")
    exit()

target_url = sys.argv[1]

url = f"https://api.github.com/repos/{OWNER}/{REPO}/actions/workflows/{WORKFLOW}/dispatches"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json"
}

data = {
    "ref": "main",
    "inputs": {
        "target_url": target_url
    }
}

response = requests.post(url, json=data, headers=headers)

if response.status_code == 204:
    print("Workflow triggered successfully!")
else:
    print("Failed:", response.text)
