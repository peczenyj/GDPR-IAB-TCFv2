# Contributing to this project

GDPR::IAB::TCFv2 is a library designed to parse iab consent strings version 2.

This is designed as a drop-in installation, so comes with some unusual
requirements.

* Works on Perl v5.12.2
* Uses only core modules (with very few exceptions)
* Uses the Artistic License 2

## Pull requests

Good pull requests - patches, improvements, new features - are a fantastic
help. They should remain focused in scope and avoid containing unrelated
commits.

**Please ask first** before embarking on any significant pull request (e.g.
implementing features, refactoring code, porting to a different language),
otherwise you risk spending a lot of time working on something that the
project's developers might not want to merge into the project.

Please adhere to the coding conventions used throughout a project (indentation,
accurate comments, etc.) and any other requirements (such as test coverage).

Follow this process if you'd like your work considered for inclusion in the
project:

* [Fork](http://help.github.com/fork-a-repo/) the project, clone your fork,
   and configure the remotes:

```bash
# Clone your fork of the repo into the current directory
git clone https://github.com/<your-username>/<repo-name>
# Navigate to the newly cloned directory
cd <repo-name>
# Assign the original repo to a remote called "upstream"
git remote add upstream https://github.com/<upstream-owner>/<repo-name>
```

* If you cloned a while ago, get the latest changes from upstream:

```bash
git checkout <dev-branch>
git pull upstream <dev-branch>
```

* Create a new topic branch (off the main project development branch) to
   contain your feature, change, or fix:

```bash
git checkout -b <topic-branch-name>
```

* Commit your changes in logical chunks. Please make your git commit message detailed and specific
   or your code is unlikely be merged into the main project. Use Git's
   [interactive rebase](https://help.github.com/articles/interactive-rebase)
   feature to tidy up your commits before making them public.

* Locally merge (or rebase) the upstream development branch into your topic branch:

```bash
git pull [--rebase] upstream <dev-branch>
```

* Push your topic branch up to your fork:

```bash
git push origin <topic-branch-name>
```

* [Open a Pull Request](https://help.github.com/articles/using-pull-requests/)
    with a clear title and description.

**IMPORTANT**: By submitting a patch, you agree to allow the project owner to
license your work under the same license as that used by the project.
