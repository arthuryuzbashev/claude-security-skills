# Contributing

Thanks for helping. New skills, new checks and better references are all welcome.

## The short version

1. Read [docs/SKILL_STANDARD.md](docs/SKILL_STANDARD.md). It is short and every skill follows it
2. Copy the layout of an existing skill (`skills/web-appsec` is a good model)
3. Standard library only, Python 3.9+, read-only behaviour
4. Add tests in `tests/test_<skill_name>.py` that run offline
5. Run `make check` (or `python3 tools/validate.py && python3 -m unittest discover -s tests`) and make sure it is green
6. Add the skill to the table in README.md

## Adding a check to an existing script

- Give it the next free rule id in that script (`HDR-033`, `IAC-021`...). Never reuse or renumber ids, people suppress findings by id
- Add one test that fires it and one that proves a safe config stays quiet
- Write the `fix` as something a developer can paste or do, not "consider improving"

## Facts

ATT&CK ids, CWE numbers, CVSS math and compliance control ids must be right. Link a source in the PR description when you add or change one.
