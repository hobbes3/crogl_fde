# Github Advisory Database for Crogl

## What does this do?
This script will download from the [GitHub's Advisory Database](https://github.com/advisories) via their respective [advisory-database project](https://github.com/github/advisory-database). The script will create a new folder called `github_advisory_database` and download or update the entire project there.

The script will also download the CISA's [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (KEV) and for each advisory, it will cross-check against the KEV and denote if it finds a match.

The script will create another folder called `csv` and each advisory will be appened to a CSV file based on severity. Lastly, the CSV files will be compressed and zipped (the original CSVs will be deleted).

## Requirements
- Python 3.13.4*
- Python dependencies; install via `pip install -r requirements.txt`
- ~5 GB of space (~4.77 GB of raw JSON from the `advisory-database` project)

*I wrote this project in Python 3.13.4, but other versions of Python 3 may still work. I recommend [`pyenv`](https://github.com/pyenv/pyenv) to manage different Python versions on your system.

## Usage
See the help message: `python get_advisories.py --help`

Note that for `--download`, it may take over 15 minutes to complete downloading and resolving all the GitHub files depending on your internet speed.

## Example installation and usage for MacOS (for beginners)
Major steps:

1. Install [Homebrew](https://brew.sh/).
2. Install [Pyenv](https://github.com/pyenv/pyenv?tab=readme-ov-file#homebrew-in-macos).
3. Install [Git](https://git-scm.com/downloads/mac).
4. Change directory to where you want download this project, for example your `Documents` folder.
5. Download/clone this project via `git`. Change to the project directory.
6. Install Python 3.13.4 via `pyenv` and select Python 3.13.4 locally.
7. Install Python dependencies via `pip`.
8. Run the script.

Open the Terminal app and enter each command (lines that start with `#` are comments don't need to be entered):
```
# Follow/confirm all prompts, especially in step 1
# Step 1
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Step 2
brew update
brew install pyenv

# Step 3
brew install git

# Step 4
cd ~/Documents/

# Step 5
git clone https://github.com/hobbes3/crogl_fde.git
cd crogl_fde/

# Step 6
pyenv install 3.13.4
pyenv local 3.13.4

# Step 7
pip install --upgrade pip
pip install -r requirements.txt

# Step 8
python get_advisories.py --download
```

## Limitations
If GitHub or CISA ever change the JSON schema, then this entire program can break.

Also, if you want to redownload the advisories, then you must manually delete the `github_advisories_database/` folder since deleting such a large folder (with 25k+ subfolders and files) will take minutes using `shutil.rmtree()` or insecurely via calling the subprocess for `sudo rm -rf` in Python.

## Thanks and Credit
I copied code from [lcnittl's answer](https://stackoverflow.com/a/71285627) on Stack Overflow for the `git clone` pretty progress bar.
