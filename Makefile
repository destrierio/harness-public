test:            ## unit + e2e
	python3 -m pytest
lint:            ## validate the manifest against the protocol schema
	python3 ../protocol/scripts/validate_harness.py harness.yaml
run-local:       ## run the real agent against the offline rig
	python3 -m testrig.run_local
diagram:         ## render docs/harness-overview.png from the Mermaid source
	npx -y @mermaid-js/mermaid-cli -i docs/harness-overview.mmd -o docs/harness-overview.png -b white -s 3
.PHONY: test lint run-local diagram
