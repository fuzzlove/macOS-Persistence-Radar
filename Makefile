.PHONY: install-dev test run build clean

install-dev:
	python3 -m pip install -e ".[dev]"

test:
	QT_QPA_PLATFORM=offscreen python3 -m pytest -q

run:
	python3 -m persistence_radar.main

build:
	python3 scripts/generate_icns.py
	python3 -m PyInstaller --clean --noconfirm macOS-Persistence-Radar.spec

clean:
	rm -rf build dist .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
