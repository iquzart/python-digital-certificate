# Variables
PYTHON := python3
VENV := venv
VENV_BIN := $(VENV)/bin
PIP := $(VENV_BIN)/pip
PYTHON_VENV := $(VENV_BIN)/python
SCRIPT := digital-cert.py
CA_DIR := CA
REQUIREMENTS := requirements.txt

# Phony targets
.PHONY: all help env install clean clean-all cert list clean-env

# Default target
all: help

# Help target
help:
	@echo "Digital Certificate Generator"
	@echo "============================="
	@echo ""
	@echo "Available targets:"
	@echo "  make env        - Create Python virtual environment"
	@echo "  make install    - Install required Python dependencies (in venv)"
	@echo "  make cert       - Generate CA and client certificates"
	@echo "  make list       - List generated certificates"
	@echo "  make clean      - Remove generated client certificates and keys"
	@echo "  make clean-env  - Remove Python virtual environment"
	@echo "  make clean-all  - Remove all certificates including CA"
	@echo "  make help       - Show this help message"
	@echo ""

# Create virtual environment
env:
	@echo "Creating Python virtual environment..."
	@$(PYTHON) -m venv $(VENV)
	@echo "Virtual environment created at ./$(VENV)"
	@echo "To activate: source $(VENV_BIN)/activate"

# Install Python dependencies
install: env
	@echo "Installing dependencies in virtual environment..."
	@if [ -f $(REQUIREMENTS) ]; then \
		$(PIP) install --upgrade pip; \
		$(PIP) install -r $(REQUIREMENTS); \
		echo "Dependencies installed successfully"; \
	else \
		echo "Warning: $(REQUIREMENTS) not found"; \
	fi

# Generate certificates
cert: $(VENV)
	@echo "Generating certificates..."
	@$(PYTHON_VENV) $(SCRIPT)

$(VENV):
	@echo "Virtual environment not found. Run 'make install' first."
	@exit 1

# List generated certificates
list:
	@echo "Generated certificates:"
	@echo "======================"
	@if [ -d $(CA_DIR) ]; then \
		echo "CA Certificates:"; \
		ls -lh $(CA_DIR)/; \
		echo ""; \
	fi
	@echo "Client/Server Certificates:"; \
	@ls -lh *.crt *.key 2>/dev/null || echo "No client certificates found"

# Clean client certificates only
clean:
	@echo "Cleaning client certificates..."
	@rm -f *.crt *.key
	@echo "Client certificates removed"

# Clean all certificates including CA
clean-all:
	@echo "WARNING: This will remove ALL certificates including CA!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo ""; \
	if [[ $REPLY =~ ^[Yy]$ ]]; then \
		rm -rf $(CA_DIR); \
		rm -f *.crt *.key; \
		echo "All certificates removed"; \
	else \
		echo "Operation cancelled"; \
	fi

# Clean virtual environment
clean-env:
	@echo "Removing virtual environment..."
	@rm -rf $(VENV)
	@echo "Virtual environment removed"
