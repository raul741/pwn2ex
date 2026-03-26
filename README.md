# pwn2ex

Automatically write vulnerabilities from a [pwndoc](https://github.com/pwndoc/pwndoc) audit to a template Excel file.

## Installation

```bash
git clone https://github.com/raul714/pwn2ex
cd pwn2ex
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements
```

## Usage

```text
usage: pwn2ex.py [-h] -i INPUT -o OUTPUT [-r ROW] [-c COLUMN] target

automatically write vulnerabilities from a pwndoc audit to a template excel file

positional arguments:
  target               target pwndoc server

options:
  -h, --help           show this help message and exit
  -i, --input INPUT    input excel template
  -o, --output OUTPUT  output processed excel file
  -r, --row ROW        specify starting row (default: 4)
  -c, --column COLUMN  specify starting column (default: B)
```

## Examples

```bash
# Basic usage (Starting row/column is "B4")
./pwn2ex.py -i template.xlsx -o out.xlsx https://pwndoc-server:8443

# Modify starting row/column to "A1"
./pwn2ex.py -i template.xlsx -o out.xlsx https://pwndoc-server:8443 -c "A" -r 1
```
