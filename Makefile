.PHONY: test

test:
	pyflakes3 ./mureq.py tests/
	flake8 mureq.py
	python3 -m unittest
