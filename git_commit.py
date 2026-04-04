import traceback
from dulwich import porcelain
from dulwich.repo import Repo

repo_path = '.'
try:
    print("Staging files...")
    # Get all untracked files and unstaged modified/deleted files using status
    status = porcelain.status(repo_path)
    
    # We add unstaged and untracked. We cannot easily do porcelain.add('.') in some older dulwich versions, 
    # but let's try porcelain.add(repo_path, paths=["."])
    porcelain.add(repo_path, paths=["."])
    
    print("Committing files...")
    commit_sha = porcelain.commit(
        repo_path, 
        message=b"Sync updates: Project Documentation, Code, EDA Charts, and VS Code Configs",
        author=b"AI Assistant <assistant@example.com>",
        committer=b"AI Assistant <assistant@example.com>"
    )
    print("Committed successfully! SHA:", commit_sha)
    
    print("Attempting to push...")
    try:
        # Dulwich push uses the remote 'origin'
        # we will see if we have rights. Often this relies on git-credential-manager. 
        # Dulwich might fail with auth here.
        porcelain.push(repo_path, "origin", "refs/heads/main")
        print("Push successful!")
    except Exception as e:
        print("Could not push automatically (maybe auth needed):", str(e))
        
except Exception as e:
    print("Error:", traceback.format_exc())
