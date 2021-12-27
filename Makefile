.PHONY: test

test:
	pyflakes3 ./mureq.py tests/
	python3 -m unittest
