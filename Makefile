.PHONY: run doctor test docker-build docker-run clean

run:
	./blackhex.sh

doctor:
	./blackhex.sh doctor

test:
	python3 -m unittest discover -s tests -v
	python3 -m compileall -q .
	bash -n install.sh scripts/nmap-vuln.sh

docker-build:
	docker compose build

docker-run:
	docker compose run --rm black-cyber-hex

clean:
	rm -rf __pycache__ blackhex/__pycache__ tests/__pycache__
