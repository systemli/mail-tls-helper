PYTHON_FILES = mail-tls-helper.py


.PHONY: dist
help:
	@echo "Makefile targets:"
	@echo "    help"
	@echo "    lint"
	@echo

.PHONY: lint
lint:
	python -m flake8 $(PYTHON_FILES)
	# TODO: fix remaining python3 style hints
	python3 -m flake8 $(PYTHON_FILES) --ignore=N802,N803,N806
