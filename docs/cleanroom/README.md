# Clean-room rewrite of the upstream-derived code

`anix-agent` started as a fork of an MPL-2.0 project. This directory holds
the specifications used to replace every file and function that still
derived from it, with a two-party process:

1. **Specification writer.** Has read the old code. Writes, per area, what
   the code must do: inputs, outputs, files and wire formats it must stay
   compatible with, and the tests that define the behaviour. The
   specifications contain no source code of the upstream project.
2. **Implementer.** A separate agent instance with a fresh context. Works
   in a copy of the repository exported with `git archive` (no git
   history) from which the files in scope were deleted, and from which
   the functions in scope of partly affected files were removed. It is
   told not to look at the upstream project in any form. It writes the
   code from the specification, the remaining code and the tests, and
   reports what it consulted.
3. The specification writer copies the implementer's files back
   unchanged except for fixes that are recorded in the pull request, runs
   the tests and opens one pull request per area.

How "upstream-derived" was measured, the before and after numbers and a
similarity check of the new code against the upstream project are in
[REPORT.md](REPORT.md).

| Area | Specification | Pull request |
|---|---|---|
| Configuration (`conf`) | [conf.md](conf.md) | #167 |
| Node configuration parsing (`api/panel`) | [panel.md](panel.md) | #168 |
| Core registry and selector (`core`) | [core.md](core.md) | #169 |
| Node controller, rate limits, certificates (`node`, `limiter`) | [node.md](node.md) | #170 |
| Command line (`cmd`, `main.go`) | [cmd.md](cmd.md) | #171 |
| Repository files (workflows, examples, module) | [repo.md](repo.md) | this pull request |
