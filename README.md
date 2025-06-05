# Github Advisory Database for Crogl

## What does this do?
This script will download from the [GitHub's Advisory Database](https://github.com/advisories) via their respective [advisory-database project](https://github.com/github/advisory-database). The script will create a new folder called `github_advisory_database` and clone the entire project there.

## Requirements
- Python 3.13.4*
- Python dependencies; install via `pip install -r requirements.txt`
- ~4 GB of space (~3.2 GB of raw JSON from the `advisory-database` project)

*I wrote this project in Python 3.13.4, but other versions of Python 3 should still work. I recommend [`pyenv`](https://github.com/pyenv/pyenv) to manage different Python versions on your system.

## Usage
Then run the script: `./python get_advisories.py`

Note that it may take up to 10 minutes to complete downloading all the GitHub files depending on your internet speed.
