.PHONY: test_root

default:

depends:
	pip3 install -r requirements.txt

lint:
	pylint main.py

tests:
	DNS_API_SECRET_KEY="14f65024b7fdd9fa91c4537cc1813354a4cb9a78c1bff59f82ca7a918bf5f4af" coverage run -m pytest -s main.py
	coverage report -m
