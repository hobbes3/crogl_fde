#!/usr/bin/env python
import argparse
import json
import requests
import zipfile
import re
import os
import pandas
import logging
import logging.handlers
import time
import threading
import shutil
from humanfriendly import format_timespan
from colorama import Fore, Style
from git import Repo
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.prompt import Confirm
from rich.live import Live
from rich.console import Console
from git_remote_progress import CloneProgress
from multiprocessing.dummy import Pool

def advisories_exist():
    return Path(project_folder + "/.git").is_dir()

def get_advisories(advisories_path):
    logger.info(f"Searching for all advisory JSONs in {advisories_path}...")
    advisories = []

    with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("{task.completed} advisories found."),
            #transient=True
            ) as progress:
        task = progress.add_task("Searching...", total=None)
        for file in Path(advisories_path).rglob("*.json"):
            progress.update(task, advance=1)
            advisories.append(file)

    return advisories

def clear_csv_folder():
    # Delete and create the CSV folder.
    csv_path = Path(csv_folder)
    if csv_path.exists():
        logger.info(f"Deleting the existing {csv_folder}/ folder.")
        shutil.rmtree(csv_path)
    csv_path.mkdir(parents=True, exist_ok=True)

def get_cve_list():
    logger.info("Downloading the Known Exploited Vulnerabilities Catalog from cisa.gov.")
    kev = requests.get(cisa_url).json()["vulnerabilities"]
    logger.info("Found {} vulnerabilities.".format(len(kev)))

    # Make a simple list containing cveID only. This will make searching more efficient later.
    cve_list = []
    for k in kev:
        cve_list.append(k["cveID"])

    return cve_list

def add_to_csv(advisory):
    thread_name = threading.current_thread().name
    with task_lock:
        if thread_name not in thread_task_map:
            # Create a new bar for this thread
            thread_task_map[thread_name] = progress.add_task(f"[green]{thread_name}", total=None, visible=True)

    task = thread_task_map[thread_name]

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
    progress.update(task, advance=1)
    progress.update(overall_task, advance=1)

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
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # URL sources
    project_url = "https://github.com/github/advisory-database"
    cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    # Folder names
    project_folder = "github_advisory_database"
    csv_folder = "csv" # Gets overwritten to "csv_test" if it's --test.

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
    parser.add_argument("-w", "--workers", type=int, default=4,
                        help="Number of workers when appending each advisory JSON to CSV. Can be set to the number of cores on your computer."
                        )
    parser.add_argument("-t", "--test", action="store_true",
                        help="Test mode. Only test a small sample of advisories that is already included with this project so the program runs in a few seconds. Will save to a separate folder called csv_test/."
                        )
    args = parser.parse_args()

    logger.info(Fore.BLUE + "Press ctrl-c to cancel at anytime..." + Style.RESET_ALL)
    pool = Pool(args.workers)

    try:
        if sum([args.download, args.update, args.test]) >= 2:
            logger.warning(Fore.RED + "You may only choose one option among --download, --update, and --test." + Style.RESET_ALL)
            exit()
        elif args.download:
            logger.info(Fore.YELLOW + "Download mode detected." + Style.RESET_ALL)

            if advisories_exist():
                logger.warning(Fore.RED + f"The {project_folder}/ folder already exist." + Style.RESET_ALL + f" Either rerun the program with --update or delete the {project_folder}/ folder yourself first.")
                exit()

            print(Fore.RED + "This will download all advisories from Github. This could take over 10 minutes (downloading about ~3.2 GB)." + Style.RESET_ALL)

            answer = Confirm.ask("Do you want to continue?")
            if not answer: exit()

            logger.info("Cloning Git repository 'advisory-database'...")
            Repo.clone_from(
                    url=project_url,
                    to_path=project_folder,
                    progress=CloneProgress()
                    )
        elif args.update:
            logger.info(Fore.YELLOW + "Update mode detected." + Style.RESET_ALL)
            if advisories_exist():
                logger.info("Pulling changes from the Git repository 'advisory-database'...")
                repo = Repo(project_folder)
                previous_head = repo.head.commit
                with Progress(
                        SpinnerColumn(),
                        TextColumn("Pulling changes..."),
                        BarColumn(),
                    ) as progress:
                    task = progress.add_task("Pulling changes", total=None)
                    pull_info = repo.remotes.origin.pull()
                current_head = repo.head.commit
                changed_files_count = len(previous_head.diff(current_head))
                logger.info(f"{changed_files_count} file(s) changed from git pull.")
            else:
                logger.warning(Fore.RED + "You need to download all advisories first before you can update." + Style.RESET_ALL + " Rerun the program with --download.")
                exit()

        if args.test:
            logger.info(Fore.YELLOW + "Test mode detected." + Style.RESET_ALL)
            advisories_path = "sample_advisories/"
            csv_folder = "csv_test"
        else:
            advisories_path = project_folder + "/advisories/"

        advisories = get_advisories(advisories_path)

        if len(advisories) == 0:
            logger.warning(Fore.RED + "No advisories found." + Style.RESET_ALL + " Rerun the program with --download or --test.")
            exit()

        clear_csv_folder()

        cve_list = get_cve_list()

        logger.info("Appending advisory JSON to CSV by severity...")
        console = Console()
        progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("{task.completed} advisories added."),
            TimeRemainingColumn()
        )

        # Dictionary to hold a task per thread
        thread_task_map = {}
        task_lock = threading.Lock()

        # Overall progress bar
        overall_task = progress.add_task("[cyan]Overall", total=len(advisories))
        with Live(progress, refresh_per_second=30, console=console):
            pool.imap_unordered(add_to_csv, advisories)
            pool.close()
            pool.join()
    except KeyboardInterrupt:
        logger.warning(Fore.RED + "Caught KeyboardInterrupt!" + Style.RESET_ALL + " Terminating workers and cleaing up. Please wait...")
        pool.terminate()
        pool.join()
    finally:
        zip_and_delete_csv()
        elapsed_time = format_timespan(time.time() - script_time_start)
        logger.info(Fore.GREEN + "Done." + Style.RESET_ALL + f" Total elapsed time: {elapsed_time}.")
