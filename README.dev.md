<img src="Certego.png" alt="Certego" width="200" />

# .github 

## 🔧 Development
To contribute to Certego CI, please:
 - clone this repository
 - follow [Setup](#📖-setup) section
 - do pull requests to `develop`.

Otherwise you can simply open an issue.


## 📖 Setup
CI files of base directory must be *hard linked* in the `.github/.github` folder, so they can be tested.
Since GitHub is not able to store the fact that these files are hardlink, you need to restore it executing [this script](.github/hooks/pre-commit) at every checkout.
From project root:
```bash
GIT_DIR=.git .github/hooks/pre-commit 
```
Also a `pre-commit` hook has been made to do it automatically:
```
cd .git/hooks
ln -s ../../.github/hooks/pre-commit
```
Now all changes will be linked and be tested with [*test* project](.github/test/) on every PR.
**Note:** Links are for the single files. If you add directories, move or add files, you need to re-execute (or even modify) the script.


### 🕑 Files to update periodically
Periodically update:
- Test projects dependencies: [Python dependencies](.github/test/python_test/packages.txt), [Node.js packages](.github/test/node_test/package.json)
- Node linters dependencies: [ESLint packages](configurations/node_linters/eslint/package.json), [Stylelint packages](configurations/node_linters/stylelint/package.json)
- [Pre-commit config](.pre-commit-config.yaml) actions revs.
- All [external actions](workflows/) revs.
- All README and docs.

### 🏷️ Release
After a new release is created, please inform final users that they should update CI subtree in their projects.
