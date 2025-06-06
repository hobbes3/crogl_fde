import argparse
import json
import shutil
import requests
import zipfile
import re
import os
import pandas as pd
from git import Repo
from git_remote_progress import CloneProgress
from pathlib import Path

project_url = "https://github.com/github/advisory-database"
project_folder = "github_advisory_database"
csv_folder = "csv"

# Command line arguments
parser = argparse.ArgumentParser(description="Download the GitHub Advisory Database and organize by severity to CSV.")
parser.add_argument("-d", "--download", action="store_true",
                    help="Download the entire advisories via git clone. This may take over 15 minutes."
                    )
parser.add_argument("-u", "--update", action="store_true",
                    help="Download only new and updated advisories via git pull."
                    )
args = parser.parse_args()

if args.download and args.update:
    print("You cannot choose both --download and --update options.")
    print("Exiting.")
elif args.download:
    print("Cloning Git repository 'advisory-database'...")
    print("Press ctrl-c to cancel.")
    Repo.clone_from(
            url=project_url,
            to_path=project_folder,
            progress=CloneProgress()
            )
    print("Done.")
elif args.update:
    print("Pulling changes from the Git repository 'advisory-database'...")
    Repo(project_folder).git.pull()
    print("Done")

#advisories_path = project_folder + "/advisories/github-reviewed/2025/06/"
advisories_path = project_folder + "/advisories/"

print("Searching for all advisories...")
advisories = list(Path(advisories_path).rglob("*.json"))
if len(advisories) == 0:
    print("No advisories in {project_folder} folder. Download advisories by rerunning the program with --download.")
    exit()
print("Found {} advisories.".format(len(advisories)))

# Delete and create the CSV folder.
print(f"Clearing the existing CSV folder.")
csv_path = Path(csv_folder)
if csv_path.is_dir():
    shutil.rmtree(csv_path)
csv_path.mkdir(parents=True, exist_ok=True)

print("Downloading the Known Exploited Vulnerabilities Catalog from cisa.gov.")
kev = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").json()["vulnerabilities"]
print("Found {} vulnerabilities.".format(len(kev)))

# Make a simple list containing cveID only. This will make searching more efficient later.
cve_list = []
for k in kev:
    cve_list.append(k["cveID"])

for advisory in advisories:
    print(advisory)
    data = json.load(open(advisory, "r"))

    # Manually add the "withdrawn" key because most advisories don't have this key and the CSV headers will get misaligned otherwise.
    data["withdrawn"] = data["withdrawn"] if "withdrawn" in data else None

    # Check for KEV.
    cve = data["aliases"][0] if data["aliases"] else None
    data["KEV"] = 1 if cve in cve_list else 0
    severity = data["database_specific"]["severity"] or "undefined"
    csv_file = csv_folder + "/" + severity.lower() + ".csv"

    df = pd.json_normalize(data)

    if Path(csv_file).exists():
        df.to_csv(csv_file, index=False, header=False, mode="a")
    else:
        df.to_csv(csv_file, index=False, header=True)

csv_severities = Path(csv_folder).glob("*.csv")

for csv_severity in csv_severities:
    severity = str(csv_severity).split(".")[0]
    print(f"Zipping {severity}.csv and deleting the original CSV.")
    zipfile.ZipFile(f"{severity}.zip", 'w', zipfile.ZIP_DEFLATED).write(csv_severity, arcname=os.path.basename(csv_severity))
    csv_severity.unlink()
