# QERDS Project Makefile
#
# Common development and CI tasks.

.PHONY: help check-traceability

# Default target
help:
	@echo "QERDS Development Tasks"
	@echo ""
	@echo "Available targets:"
	@echo "  check-traceability  - Validate requirements traceability coverage"
	@echo "  help                - Show this help message"

# Validate that all requirements have traceability entries (REQ-A04)
check-traceability:
	@python3 scripts/check-traceability.py
