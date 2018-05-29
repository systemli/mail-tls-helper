PYTHON_LOCATIONS = mail-tls-helper.py tests
SHELL_SCRIPTS = munin-plugin


.PHONY: dist
help:
	@echo "Makefile targets:"
	@echo "    help"
	@echo "    lint"
	@echo "    test"
	@echo

.PHONY: test
test:
	python -m unittest tests
	python3 -m unittest discover

.PHONY: lint
lint:
	@# keep these commands in sync with the "script" section of .travis.yml
	python -m flake8 $(PYTHON_LOCATIONS)
	# TODO: fix remaining python3 style hints
	python3 -m flake8 $(PYTHON_LOCATIONS) --ignore=N802,N803,N806
	shellcheck -s dash $(SHELL_SCRIPTS)
