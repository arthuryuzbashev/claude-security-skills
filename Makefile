.PHONY: check test validate install link

check: validate test

validate:
	python3 tools/validate.py

test:
	python3 -m unittest discover -s tests -v

install:
	./install.sh

link:
	./install.sh --link
