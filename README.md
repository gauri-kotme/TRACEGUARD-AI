# TRACEGUARD AI

TRACEGUARD AI is a Python-based file safety and integrity checking tool built with Streamlit. It helps users identify suspicious file characteristics and check whether a file has changed since it was marked as trusted.

## What it does

- **File scanning:** Checks filenames, extensions, and file headers for suspicious patterns.
- **Risk score:** Gives a score from 0 to 100 based on rule-based checks and explains the findings.
- **File integrity checking:** Uses SHA-256 hashes to check whether a file matches its trusted baseline.
- **Scan history:** Stores scan records in a local SQLite database so previous results can be reviewed.
- **Reports:** Lets users download scan results as JSON and TXT files.
- **Test cases:** Includes sample files and automated tests to check the main features.

## How it works

1. Upload a file or choose a sample file.
2. TRACEGUARD AI checks its filename, extension, and available file signatures.
3. The risk engine checks for suspicious patterns and calculates a score.
4. If a trusted baseline exists, the app compares the file's SHA-256 hash with the saved hash.
5. Review the result, check the scan history, or download a report.

**Risk score and file integrity are different.** A low risk score does not mean that a file is unchanged. Similarly, a changed file is not automatically malicious.

## Tech stack

- Python
- Streamlit
- SQLite
- SHA-256 hashing
- Pytest

## Getting started

### Requirements

- Python 3.10 or newer
- Git (optional, for cloning the repository)

### 1. Clone the repository

```bash
git clone https://github.com/gauri-kotme/TRACEGUARD-AI.git
cd TRACEGUARD-AI
```

### 2. Create a virtual environment

On Windows:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
py -m pip install -r requirements.txt
```

### 4. Run the application

```powershell
py -m streamlit run app.py --server.port 8503
```

Open this address in your browser:

http://localhost:8503

### 5. Run the tests

```powershell
py -m pytest -q
```

## Project structure

```text
TRACEGUARD-AI/
├── app.py                 # Streamlit application
├── requirements.txt       # Python dependencies
├── traceguard.db          # Local database, created when needed
├── traceguard/
│   ├── analyzer.py        # File analysis
│   ├── config.py          # Configuration
│   ├── database.py        # Scan history and database operations
│   ├── hasher.py          # File hashing and integrity checks
│   ├── reports.py         # Report generation
│   ├── risk_engine.py     # Rule-based risk scoring
│   └── synthetic.py       # Synthetic test cases
├── samples/               # Sample files for testing
└── tests/                 # Automated tests
```

## Limitations

TRACEGUARD AI uses rule-based checks; it is not a full antivirus program or a trained machine-learning malware detector. Its risk score is an indicator score, not the probability that a file contains malware.

A file can still be harmful even if the scan finds no suspicious patterns. Use caution with files from unknown sources.

## Author

**Gauri Kotme**

GitHub: [gauri-kotme](https://github.com/gauri-kotme)
