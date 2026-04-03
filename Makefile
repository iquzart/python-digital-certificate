PYTHON ?= python3
VENV ?= venv
PYTHON_BIN := $(VENV)/bin/python
PIP := $(PYTHON_BIN) -m pip
SCRIPT := digital-cert.py
CA_DIR := CA

.PHONY: all help env venv install cert run list check audit clean clean-all clean-artifacts clean-env

all: help

help:
	@printf "Digital Certificate Generator\n\n"
	@printf "Available targets:\n"
	@printf "  make env|venv        Create the Python virtual environment\n"
	@printf "  make install         Install project dependencies\n"
	@printf "  make cert|run        Generate CA and client certificates\n"
	@printf "  make list            List generated certificates\n"
	@printf "  make check           Compile-check the Python script\n"
	@printf "  make audit           Audit Python dependencies\n"
	@printf "  make clean           Remove generated client certificates and keys\n"
	@printf "  make clean-all       Remove all generated certificates including the CA\n"
	@printf "  make clean-env       Remove the virtual environment\n"

$(PYTHON_BIN):
	$(PYTHON) -m venv $(VENV)

$(VENV)/.installed: requirements.txt | $(PYTHON_BIN)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	touch $(VENV)/.installed

$(VENV)/.audit-installed: | $(PYTHON_BIN)
	$(PIP) install pip-audit
	touch $(VENV)/.audit-installed

env: venv

venv: $(PYTHON_BIN)

install: $(VENV)/.installed

cert: $(VENV)/.installed
	$(PYTHON_BIN) $(SCRIPT)

run: cert

list:
	@if [ -d "$(CA_DIR)" ]; then ls -lh "$(CA_DIR)"; else printf "No CA directory found\n"; fi
	@ls -lh *.crt *.key 2>/dev/null || printf "No client certificates found\n"

check: $(VENV)/.installed
	$(PYTHON_BIN) -m py_compile $(SCRIPT)

audit: $(VENV)/.installed $(VENV)/.audit-installed
	$(PYTHON_BIN) -m pip_audit -r requirements.txt

clean:
	rm -f *.crt *.key

clean-all: clean
	rm -rf $(CA_DIR)

clean-artifacts: clean-all

clean-env:
	rm -rf $(VENV) __pycache__
