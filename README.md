# Lenchar Web Editor

A simple Flask app to decode, edit, and re-encode `.lenchar` files (custom gzip-wrapped format).

## Features

- Upload a `.lenchar` file
- Decode and display its plaintext contents
- Edit inline in your browser
- Download:
  - the raw decoded text (`.txt`)
  - a newly re-encoded `.lenchar` file

## Technology

- Conda
- Python 3
- Flask
- Tailwind CSS (via CDN)

## Setup

1. Clone the repo:
```bash
git clone https://github.com/<your-username>/lenchar-web-editor.git
cd lenchar-web-editor
```
2.	(Optional) Create a virtualenv and activate:
```bash
conda env create -f environment.yml
conda activate lenchar_editor
```
3.	Run the app:
```bash
python app.py
```
4.	Open your browser at http://127.0.0.1:5000.

## Usage

1.	Upload your .lenchar file on the home page.
2.	Edit the decoded text in the textarea.
3.	Download either the raw text or the re-encoded .lenchar.





