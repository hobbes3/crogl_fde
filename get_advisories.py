import pandas
import argparse
from git import Repo
from git_remote_progress import CloneProgress
from pathlib import Path

project_url = "https://github.com/github/advisory-database"
project_folder = "github_advisory_database"

# Command line arguments
parser = argparse.ArgumentParser(description="Download and simplify the GitHub Advisory Database to CSV.")
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

advisories_path = project_folder + "/advisories/github-reviewed/2025/06/"

for file in Path(advisories_path).rglob("*.json"):
    print(file)
