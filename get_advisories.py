#!/usr/bin/env python
import argparse
import json
import shutil
import requests
import zipfile
import re
import os
import pandas
import logging
import logging.handlers
import time
from colorama import Fore, Style
from git import Repo
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Confirm
from git_remote_progress import CloneProgress
from multiprocessing.dummy import Pool

def advisories_exist():
    return Path(project_folder + "/.git").is_dir()

def get_advisories():
    logger.info(f"Searching for all advisories in {project_folder}/advisories/...")
    advisories = []

    with Progress(
            SpinnerColumn(),
            TextColumn("Searching..."),
            BarColumn(),
            TextColumn("{task.completed} advisories found."),
            #transient=True
            ) as progress:
        task = progress.add_task("Finding advisories", total=None)
        for file in Path(advisories_path).rglob("*.json"):
            progress.update(task, advance=1)
            advisories.append(file)

    return advisories

def clear_csv_folder():
    # Delete and create the CSV folder.
    logger.info(f"Clearing the existing CSV folder.")
    csv_path = Path(csv_folder)
    shutil.rmtree(csv_path, ignore_errors=True)
    csv_path.mkdir(parents=True, exist_ok=True)

def get_cve_list():
    logger.info("Downloading the Known Exploited Vulnerabilities Catalog from cisa.gov.")
    kev = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").json()["vulnerabilities"]
    logger.info("Found {} vulnerabilities.".format(len(kev)))

    # Make a simple list containing cveID only. This will make searching more efficient later.
    cve_list = []
    for k in kev:
        cve_list.append(k["cveID"])

    return cve_list

def add_to_csv(advisory):
    logger.debug(advisory)
    data = json.load(open(advisory, "r"))

    # Manually add the "withdrawn" key because most advisories don't have this key and the CSV headers will get misaligned otherwise.
    data["withdrawn"] = data["withdrawn"] if "withdrawn" in data else None

    # Check for KEV.
    cve = data["aliases"][0] if data["aliases"] else None
    data["KEV"] = 1 if cve in cve_list else 0
    severity = data["database_specific"]["severity"] or "undefined"
    csv_file = csv_folder + "/" + severity.lower() + ".csv"

    df = pandas.json_normalize(data)

    if Path(csv_file).exists():
        df.to_csv(csv_file, index=False, header=False, mode="a")
    else:
        df.to_csv(csv_file, index=False, header=True)

def zip_and_delete_csv():
    csv_severities = Path(csv_folder).glob("*.csv")
    for csv_severity in csv_severities:
        severity = str(csv_severity).split(".")[0]
        logger.info(f"Zipping {severity}.csv and deleting the original CSV.")
        zipfile.ZipFile(f"{severity}.zip", 'w', zipfile.ZIP_DEFLATED).write(csv_severity, arcname=os.path.basename(csv_severity))
        csv_severity.unlink()

if __name__ == '__main__':
    script_time_start = time.time()

    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-7s] (%(threadName)-10s) %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    project_url = "https://github.com/github/advisory-database"
    project_folder = "github_advisory_database"
    csv_folder = "csv"

# Command line arguments
    parser = argparse.ArgumentParser(
            description="Download the GitHub Advisory Database and organize by severity to CSV.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
            )
    parser.add_argument("-d", "--download", action="store_true",
                        help="Download the entire advisories via git clone. This may take over 15 minutes."
                        )
    parser.add_argument("-u", "--update", action="store_true",
                        help="Download only new and updated advisories via git pull."
                        )
    parser.add_argument("-t", "--threads", type=int, default=4,
                        help="Number of threads when appending each advisory JSON to CSV."
                        )
    parser.add_argument("-x", "--debug", action="store_true",
                        help="Debug mode. More debug messages. Only test a small portion of the advisories."
                        )
    args = parser.parse_args()

    logger.info(Fore.BLUE + "Press ctrl-c to cancel at anytime..." + Style.RESET_ALL)
    pool = Pool(args.threads)

    try:
        if args.debug:
            logger.setLevel(logging.DEBUG)
            logger.debug("DEBUG MODE ON!")

        if args.download and args.update:
            logger.warning(Fore.RED + "You cannot choose both --download and --update options!" + Style.RESET_ALL)
            logger.info("Exiting.")
            exit()
        elif args.download:
            if advisories_exist():
                warning_msg = "This will delete all existing advisories and download them all again from GitHub."
            else:
                warning_msg = "This will download all advisories from GitHub."

            print(Fore.RED + warning_msg + " This could take over 10 minutes." + Style.RESET_ALL)

            answer = Confirm.ask("Do you want to continue?")
            if answer:
                logger.info(f"Deleteing {project_folder} folder...")
                shutil.rmtree(Path(project_folder), ignore_errors=True)
                logger.info("Cloning Git repository 'advisory-database'...")
                Repo.clone_from(
                        url=project_url,
                        to_path=project_folder,
                        progress=CloneProgress()
                        )
                logger.info("Done.")
            else:
                logger.info("Exiting.")
                exit()
        elif args.update:
            if advisories_exist():
                logger.info("Pulling changes from the Git repository 'advisory-database'...")
                with Progress(
                        SpinnerColumn(),
                        TextColumn("Pulling changes..."),
                        BarColumn(),
                    ) as progress:
                    task = progress.add_task("Pulling changes", total=None)
                    Repo(project_folder).git.pull()
                    progress.update(task, advance=1)

                logger.info("Done")
            else:
                logger.warning(Fore.RED + "You need to download all advisories first before you can update. Rerun the program with --download option." + Style.RESET_ALL)
                logger.info("Exiting.")
                exit()


        if args.debug:
            logger.debug("Only grabbing only a small list of advisories.")
            advisories_path = project_folder + "/advisories/github-reviewed/2022/05/"
        else:
            advisories_path = project_folder + "/advisories/"

        advisories = get_advisories()

        if len(advisories) == 0:
            logger.warning(Fore.RED + "No advisories in {project_folder} folder. Download advisories by rerunning the program with --download." + Style.RESET_ALL)
            exit()

        clear_csv_folder()

        cve_list = get_cve_list()

        pool.imap_unordered(add_to_csv, advisories)
        pool.close()
        pool.join()
    except KeyboardInterrupt:
        logger.warning(Fore.RED + "Caught KeyboardInterrupt! Terminating workers and cleaing up. Please wait..." + Style.RESET_ALL)
        pool.terminate()
        pool.join()
    finally:
        zip_and_delete_csv()
        elapsed_time = "{:.2f}".format(time.time() - script_time_start)
        logger.info(Fore.GREEN + "Done." + Style.RESET_ALL + f" Total elapsed time: {elapsed_time} seconds.")
