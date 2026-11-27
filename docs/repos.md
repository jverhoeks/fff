# Git repos: duplicates and "what would deleting this lose"

At the end of every scan, fff reads each checkout's `.git` directly and fills the `repos` table. It never runs `git` and never
fetches. The code is in `src/repos.rs` (discovery and remotes) and `src/gitstate.rs` (the local-work check).

## What is recorded

| column | meaning |
|---|---|
| `kind` | `repo`; `worktree` (a linked worktree; its history lives in `main`); `submodule`; or `vendored` (a clone inside another repo under a hidden tool dir such as `.terraform` or `.external_modules`) |
| `remote`, `remote_key` | the origin URL with credentials removed, and a normalised `host/owner/name`. Two checkouts with the same key are the same project, whether they were cloned over ssh or https. |
| `branch`, `head`, `activity` | the current branch (NULL when detached), the HEAD commit, and the newest mtime of index / logs/HEAD / HEAD |
| `worktrees`, `unpushed`, `stash`, `changed` | the raw counts behind the verdict |
| `at_risk`, `risk` | 1 = local work found, 0 = no sign of it, NULL = could not check. `risk` is the one-line verdict. |

## The local-work check

Each item below is something deleting the checkout would lose or break:

| check | how it is read |
|---|---|
| **main repo of N worktrees** | `.git/worktrees/*/gitdir` entries whose folder still exists. Deleting the main repo breaks all of them, wherever they live. |
| **no remote** | no `[remote …]` in the config: every branch exists only here |
| **unpushed branches** | a local branch whose tip was never the value of a remote-tracking ref: refs/remotes, packed-refs and, only when needed, the remote reflogs |
| **detached HEAD commit** | HEAD on a commit that is on no branch and no remote ref |
| **stash** | `refs/stash`, loose or packed |
| **staged changes** | the root of the index's cache-tree (TREE) extension is invalidated: `git add` since the last commit |
| **tracked files edited or deleted** | each index entry's size and mtime (v2–v4 index) compared with the file on disk; skip-worktree and assume-unchanged entries included |
| **merge / rebase / cherry-pick / revert / bisect in progress** | the marker files in the git dir |

These count as **unknown**, never "clean": reftable refs, sha256 repos, split or sparse indexes, an unreadable `.git`.

Branches, stashes and worktrees are counted on the repo that owns them. A worktree's own row shows only its edited files, and
it suggests `git worktree remove`.

### How it was validated

- **Main checks** (worktrees, unpushed branches, stashes, edited files). Compared with what `git` itself reports on 100 real
  repos: 0 missed, 0 false alarms.
- **Staged-changes check.** Compared with `git diff --cached` on about 1,200 real repos. It caught 12 of 15 repos with staged
  changes and flagged 9 clean repos. That errs towards a warning.
- **Unit test.** `src/gitstate.rs` builds throwaway repos with the git binary (in tests only) and checks each case.

### What it can't see

- **Untracked files.** Checking them needs full `.gitignore` evaluation. Look before you delete.
- **An edit that keeps the size and mtime** (`cp -p`, `touch -r`). This is inherent to comparing stats.
- **Stale remote refs.** If a branch was pushed and the remote was later force-pushed or deleted without you fetching, the
  local tip still counts as pushed.
- **Submodules.** A submodule's unpushed commits show on the submodule's own row, not on its superproject's. The treemap's Trash
  guard does check every checkout under the path, submodules included.

## Cleaning up duplicates

```console
$ fff repos --dups
remote                     copies  kind      path                       branch      size  build/deps  local work
github.com/example/webapp       2  repo      /Users/me/old/webapp-copy  main         29K         35B  no sign of local work
github.com/example/webapp       2  repo      /Users/me/src/webapp       main        1.6M        1.5M  1 unpushed branch (feature/login)
github.com/example/tool         2  repo      /Users/me/src/tool         main        5.8M        5.7M  main repo of 1 worktree in /Users/me/src (1) (deleting it breaks them)
github.com/example/tool         2  worktree  /Users/me/src/tool-fix     fix/parser  245B          0B  no sign of local work; worktree: drop with `git worktree remove`, not the Trash
```

1. **Free build output first.** It can be rebuilt and is usually most of the bytes:
   ```sh
   fff repos -s junk                 # repos by build/deps bytes
   fff big --name target             # every Rust target/ dir
   fff big --name node_modules
   ```
2. **Remove worktrees with git:** `git -C <main repo> worktree remove <path>`. fff prints the command but never runs it.
3. **Never delete a "main repo of N worktrees".**
4. **For "no sign of local work":** check for untracked files (`git status`), then delete. The treemap's Move to Trash re-runs
   the check live and asks again if anything turned up since the scan.

## SQL

```sql
-- duplicate checkouts
SELECT remote_key, count(*) FROM repos WHERE kind <> 'vendored' GROUP BY 1 HAVING count(*) > 1;

-- the biggest checkouts that are safe by this check
SELECT r.path, s.bytes, r.risk FROM repos r JOIN dir_stats s ON s.dir = r.dir
WHERE r.at_risk = 0 ORDER BY s.bytes DESC LIMIT 20;

-- repos with history that exists nowhere else
SELECT path, branch, risk FROM repos WHERE remote IS NULL AND kind = 'repo';

-- main repos whose worktrees are spread around
SELECT path, worktrees, risk FROM repos WHERE worktrees > 0 ORDER BY worktrees DESC;
```
