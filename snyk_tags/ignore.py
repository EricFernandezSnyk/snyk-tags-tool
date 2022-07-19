#! /usr/bin/env python3

import logging
import httpx
import typer
import json
from rich.pretty import pprint

from snyk_tags import __app_name__, __version__


logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)

app = typer.Typer()

# Reach to the API and generate tokens
def create_client(token: str) -> httpx.Client:
    return httpx.Client(
        base_url="https://snyk.io/api/v1", headers={"Authorization": f"token {token}", 'Content-Type': 'application/json'}
    )


# Apply tags to a specific project
def apply_ignore_dependency(
    client: httpx.Client, org_id: str, project_id: str, issue_id: str
) -> tuple:
    
    ignore_data = json.dumps({
        "ignorePath": "",
        "reason": "",
        "reasonType": "not-vulnerable",
        "disregardIfFixable": False,
        "expires": "2099-10-31T11:24:00.932Z"
    })

    req = client.post(f"org/{org_id}/project/{project_id}/ignore/{issue_id}", data=ignore_data)

    ig_data = typer.style(ignore_data, bold=True, fg=typer.colors.MAGENTA)
    if req.status_code == 200:
        logging.info(f"Successfully ignored Issue: {issue_id}.")
    if req.status_code == 422:
        logging.warning(f"Data {ig_data} cannot be processed, make sure you have written the correct values (refer to help or Readme) and that they are in low caps.")
    if req.status_code == 404:
        logging.error(f"Project not found, likely a READ-ONLY project. Project: {project_id}. Error message: {req.json()}.")
    if req.status_code == 500:
        logging.error(f"Error {req.status_code}: Internal Server Error. Please contact eric.fernandez@snyk.io.")

    return req.status_code, req.json()

#
#introThrough = json.dumps({"includeIntroducedThrough": True})
def ignore_project_issues(token: str, org_ids: list) -> None:
    with create_client(token=token) as client:
        for org_id in org_ids:
            projects = client.post(f"org/{org_id}/projects").json()
            for project in projects.get("projects"):
                pid = project["id"]
                issues = client.post(f"org/{org_id}/project/{pid}/aggregated-issues").json()
                for issue in issues["issues"]:
                    if "com.fasterxml.jackson.core:jackson-databind" in issue["pkgName"]:
                        print('Found a good issue')
                        pprint(issue)
                    #else:
                    #    iid = issue["id"]
                    #    print('Found the paths')
                    #    paths = client.get(f"org/{org_id}/project/{pid}/issue/{iid}/paths").json()
                    #    for path in paths["paths"]:
                    #        print('We are in the path now')
                    #        pprint(path)
                        
                        
                        #apply_ignore_dependency(client=client, org_id=org_id, project_id=project["id"], issue_id=issue["id"])

@app.command(help=f"Ignore dependency")
def dependency(org_id: str = typer.Option(
            ..., # Default value of comamand
            envvar=["ORG_ID"],
            help="pecify the Organization ID where you want to apply the ignore"
        ),  token: str = typer.Option(
            ..., # Default value of comamand
            help="SNYK API token",
            envvar=["SNYK_TOKEN"]
        )
    ):
    #typer.secho(f"\nAdding the tag key {tagKey} and tag value {tagValue} to projects within {collectionName} for easy filtering via the UI", bold=True)
    ignore_project_issues(token,[org_id])




