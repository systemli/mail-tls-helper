PYTHON_LOCATIONS = mail-tls-helper.py tests


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
	python -m flake8 $(PYTHON_LOCATIONS)
	# TODO: fix remaining python3 style hints
	python3 -m flake8 $(PYTHON_LOCATIONS) --ignore=N802,N803,N806
