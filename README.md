# Github Advisory Database for Crogl

## What does this do?
This script will download from the [GitHub's Advisory Database](https://github.com/advisories) via their respective [advisory-database project](https://github.com/github/advisory-database). The script will create a new folder called `github_advisory_database` and clone the entire project there.

## Requirements
- Python 3.13.4*
- Python dependencies; install via `pip install -r requirements.txt`
- ~5 GB of space (~4.77 GB of raw JSON from the `advisory-database` project)

*I wrote this project in Python 3.13.4, but other versions of Python 3 should still work. I recommend [`pyenv`](https://github.com/pyenv/pyenv) to manage different Python versions on your system.

## Usage
Run the main script: `python get_advisories.py`

Note that it may take up to 15 minutes to complete downloading and resolving all the GitHub files depending on your internet speed.

## Example usage for MacOS (for beginners)
Major steps:

1. Install [Homebrew](https://brew.sh/)
2. Install [pyenv](https://github.com/pyenv/pyenv?tab=readme-ov-file#homebrew-in-macos)
3. Install [Git](https://git-scm.com/downloads/mac)
4. Change directory to where you want download this project, for example your `Documents` folder
5. Download/clone this project via `git`
6. Install Python 3.13.4 via `pyenv` and select Python 3.13.4 locally
7. Install Python dependencies via `pip`
8. Run the script

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

# Step 6
pyenv local 3.13.4

# Step 7
pip install --upgrade pip
pip install -r requirements.txt

# Step 8
python get_advisories.py
```

## Thanks
I copied code from `lcnittl`'s answer on Stack Overflow for the `git clone` pretty progress bar.
