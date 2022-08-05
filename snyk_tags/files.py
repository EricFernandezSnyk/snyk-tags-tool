#! /usr/bin/env python3
import typer
from pathlib import Path
from typing import List
import csv
from snyk_tags import collection, attribute
from rich import print

app = typer.Typer()
repoexample = typer.style("'snyk-labs/nodejs-goof'", bold=True, fg=typer.colors.MAGENTA)
tagexample = typer.style("org-id,target,key,value", bold=True, fg=typer.colors.MAGENTA)
attributesexample = typer.style("org-id,target,criticality,environment,lifecycle", bold=True, fg=typer.colors.MAGENTA)

@app.command(help=f"Apply a custom tag from a csv to a target, for example {repoexample} \n\n The csv must be in the format {tagexample}")
def target_tag(files: List[Path] = typer.Option(...,help=f"csv file with the format {tagexample}"),
    snyktkn: str = typer.Option(...,help="Snyk API token with org admin access",envvar=["SNYK_TOKEN"])):
    for path in files:
        if path.is_file():
            file = open(path)
            csvreader = csv.DictReader(file)
            for row in csvreader:
                org_id = row.get("org-id")
                target = row.get("target")
                key = row.get("key")
                value = row.get("value")
                collection.apply_tags_to_projects(snyktkn, [org_id], target, value, key)
        else:
            print(f"The file or path does not exist")

@app.command(help=f"Apply attributes from a csv to a target, for example {repoexample} \n\n The csv must be in the format {attributesexample}")
def target_attributes(files: List[Path] = typer.Option(...,help=f"csv file with the format {attributesexample}"),
    snyktkn: str = typer.Option(...,help="Snyk API token with org admin access",envvar=["SNYK_TOKEN"])):
    for path in files:
        if path.is_file():
            file = open(path)
            csvreader = csv.DictReader(file)
            for row in csvreader:
                org_id = row.get("org-id")
                target = row.get("target")
                criticality = row.get("criticality")
                environment = row.get("environment")
                lifecycle = row.get("lifecycle")
                attribute.apply_attributes_to_projects(snyktkn, [org_id], target, [criticality], [environment], [lifecycle])
        else:
            print(f"The file or path does not exist")
