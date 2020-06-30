#Contributing to KRATE

If you wish to add a new assembly, please make sure the assembly targets .NET Standard 2.0.

Pull Requests

    DO submit all code changes via pull requests (PRs) rather than through a direct commit. PRs will be reviewed and potentially merged by the repo maintainers after a peer review that includes at least one maintainer.
    DO NOT submit "work in progress" PRs. A PR should only be submitted when it is considered ready for review and subsequent merging by the contributor.
    DO give PRs short-but-descriptive names (e.g. "Improve code coverage for System.Console by 10%", not "Fix #1234")
    DO refer to any relevant issues, and include keywords that automatically close issues when the PR is merged.
    DO tag any users that should know about and/or review the change.
    DO ensure each commit successfully builds.
    DO address PR feedback in an additional commit(s) rather than amending the existing commits, and only rebase/squash them when necessary. This makes it easier for reviewers to track changes.
    DO assume that "Squash and Merge" will be used to merge your commit unless you request otherwise in the PR.
    DO NOT fix merge conflicts using a merge commit. Prefer 'git rebase'.
    DO NOT mix independent, unrelated changes in one PR. Separate real product/test code changes from larger code formatting/dead code removal changes. Separate unrelated fixes into separate PRs, especially if they are in different assemblies.

# C# Coding Style

For non code files (xml, etc), our current best guidance is consistency. When editing files, keep new code and changes consistent with the style in the files. For new files, it should conform to the style for that component. If there is a completely new component, anything that is reasonably broadly accepted is fine.

An EditorConfig file (.editorconfig) has been provided at the root of the repository, enabling C# and .NET auto-formatting.

# Unit Test

Using test driven development will make the following easier:

	1. If you find a component that does not have a unit test. Please write a unit test for it.
	2. If you create a new component please write a unit test for it as well.
	3. If you edit an existing component and the changes required the unit test be change, please make the necessary edits to the unit test.