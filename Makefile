default: run

run: webcrawler
	python3 -m venv crawler
	./crawler/bin/pip install beautifulsoup4
	./crawler/bin/pip install autopep8
clean:
	rm -rf crawler
