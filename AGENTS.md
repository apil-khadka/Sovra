# Agent instructions

Before planning work or writing files, read `.intel/README.md` if it exists for local context and note-storage rules.
Keep conversation summaries, temporary plans, hackathon discussions, and other internal working notes under `.intel/`.
Use public `docs/` for reviewed project documentation that contributors and organizers need.

If the local guide is absent, follow the storage rule above and continue using public project documentation.
The project must remain understandable and runnable without private files.

Before committing or pushing, check `git ls-files` for `.intel/` paths and exclude them from the change.
Never force-add ignored private files or copy their contents into public issues, pull requests, or documentation.
