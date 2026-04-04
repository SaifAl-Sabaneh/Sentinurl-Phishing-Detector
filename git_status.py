import traceback
from dulwich import porcelain

repo_path = '.'
try:
    status = porcelain.status(repo_path)
    print('Staged:', status.staged)
    print('Unstaged:', status.unstaged)
    print('Untracked:', status.untracked)
except Exception as e:
    print(traceback.format_exc())
