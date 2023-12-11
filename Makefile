.PHONY: test_root

default:

depends:
	pip3 install -r requirements.txt

lint:
	pylint main.py

tests:
	coverage run -m pytest -s main.py
	coverage report -m
