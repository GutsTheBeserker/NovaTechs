"""Script to download the authentic Vrbančič et al. (2020) phishing dataset.

Dataset: Mendeley / IEEE Data in Brief Phishing Websites Benchmark Dataset
Source: https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv
License: CC BY 4.0
"""

import sys
import urllib.request
from pathlib import Path

DATA_URL = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = REPO_ROOT / "data" / "raw"
OUTPUT_FILE = OUTPUT_DIR / "dataset_small.csv"


def download_dataset(force: bool = False) -> Path:
    """Download the dataset if not already present."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if OUTPUT_FILE.exists() and not force:
        file_size = OUTPUT_FILE.stat().st_size
        if file_size > 100_000:
            print(f"Dataset already exists at {OUTPUT_FILE} ({file_size:,} bytes). Skipping download.")
            return OUTPUT_FILE

    print(f"Downloading authentic phishing dataset from {DATA_URL}...")
    try:
        urllib.request.urlretrieve(DATA_URL, OUTPUT_FILE)
        file_size = OUTPUT_FILE.stat().st_size
        print(f"Download complete: {OUTPUT_FILE} ({file_size:,} bytes)")
        return OUTPUT_FILE
    except Exception as exc:
        print(f"Failed to download dataset: {exc}", file=sys.stderr)
        raise


if __name__ == "__main__":
    download_dataset()
