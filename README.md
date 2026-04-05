<div align="center">
  <h1>🔍 CredFinder</h1>
  <p><strong>A blazingly fast, multi-mode Python CLI tool designed to safely parse, filter, and extract credential pairs from massive raw string dumps (URL:LOGIN:PASSWORD).</strong></p>
</div>

---

## 🚀 Features

- **Dual-Mode Execution:** Double-click the file to launch a gorgeous, arrow-key navigable Interactive Menu—or call it strictly via CLI arguments for complete automation.
- **Advanced Target Filtering:** Don't just search domains. Target specific fields directly:
  - `URL` (Match specific domains)
  - `Email` (Match logins containing `@`)
  - `Username` (Match logins without `@`)
  - `Password` (Match isolated password structures to check weak security)
  - `Regex (Advanced)` (Use raw regular expressions like `.*@netflix\.com` across the entire line)
- **Gigabyte Memory-Safe Streamer:** Opens target files and streams them one line at a time. It will parse a 50GB file instantly without overloading your RAM or crashing, complete with a live `tqdm` progress bar. 
- **Auto-Fuzzy Fallback:** Built-in misspelling defense relying on `difflib.SequenceMatcher`. If your standard match yields zero results, it will automatically search internally for 60% probability matches (e.g. `g2g.com` matching `g2.com`).
- **Domain Sorting Output:** Neatly takes thousands of wild lines and groups them strictly by their base domain. (Extracts `Facebook`, `Paypal`, `Netflix` into structured cluster views natively).
- **GUI OS File Pickers:** Seamless integration natively with Windows! Need to select a folder? Don't type it—a native OS selection popup opens automatically.

---

## 🛠️ Installation

CredFinder uses built-in Python logic natively but relies on a few UX modules to provide the gorgeous Terminal graphics. 

```bash
# Clone the repository
git clone https://github.com/yourusername/CredFinder.git
cd CredFinder

# Install UX Dependencies
pip install questionary colorama tqdm
```
*(Note: If installed on an SSH server lacking these libraries, CredFinder cleanly degrades back to plain-text fallback methods automatically so it never stops functioning.)*

---

## 🕹️ Usage

### Interactive Menu Mode (Recommended)
Simply launch the python script with zero arguments.
```bash
python credfinder.py
```
This triggers the native prompt. You can select single files, deeply recursing folders, maintain custom 5-state search histories, toggle exact matches, and auto-detect your latest edited `.txt` files in the repository.

### CLI Automation Mode
Perfect for scripting workflows or headless pipelines.

```bash
python credfinder.py -q "facebook, paypal" -t URL -f my_data.txt --exact
```

**Available Flags:**
- `-q`, `--query`     : Keyword(s) to search, comma-separated (e.g. paypal,g2g).
- `-f`, `--file`      : Path to a single TXT file to scan.
- `-d`, `--dir`       : Recursively scans all `.txt` files inside target folder.
- `-t`, `--type`      : Target field or search type: `URL`, `Email`, `Username`, `Password`, `All`, `Regex`. (Defaults: `URL`)
- `-o`, `--output`    : Force saving the output layout to this exact filepath.
- `--exact`           : Force exact base-domain matching rather than partial substring matching.
- `-v`, `--verbose`   : Show skipped/malformed structural line counts.

---

## ⚙️ How It Works

#### 1. Stream Reading:
Reads `raw_line` from large dumps into `parse_line()`.
#### 2. Protocol Bypass: 
Splits `https://www.paypal.com/signin:user@gmail:pass` strictly over the last two colons ensuring pre-existing HTTP colliders don't ruin list assignments.
#### 3. Match Checking:
Routes fields through `match_by_type()` checking `search_type` switches and `Regex.compile()` matches.
#### 4. Formatting: 
Passes matched tuples into isolated dictionaries representing `base_domains`, returning clean user-facing terminal logs and `.txt` results.

---

## ⚠️ Disclaimer
**Educational and Defensive Tools Only.** CredFinder is built explicitly for system administrators, infosec teams, and password-auditing professionals to securely parse internal security dumps. Do not use this tool on sensitive data you have not been granted explicit administrative consent to operate on.
