import git
from git_remote_progress import GitRemoteProgress

project_url = "https://github.com/github/advisory-database"

print("Cloning Git Repository 'advisory-database' ('main' branch)...")
print("Press ctrl-c to cancel.")
git.Repo.clone_from(
    url=project_url,
    to_path="github_advisory_database",
    progress=GitRemoteProgress(),
)
print("Done.")
