"""
CredFinder - A fast CLI tool to search credentials inside TXT files.
Format expected: URL:LOGIN:PASSWORD
"""

import argparse
import difflib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# Graceful import of optional dependencies
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    import questionary
    from questionary import Style as QStyle
    QUESTIONARY_AVAILABLE = True
except ImportError:
    QUESTIONARY_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Color helpers (fallback to plain text if colorama not installed)

"""
DESCRIPTION:
This section defines helper wrapper functions (e.g., color_red, color_cyan) that wrap terminal
output in ANSI escape codes using the 'colorama' library. This makes the CLI look beautiful
and easy to read. If 'colorama' is not installed, it gracefully returns plain text so the
script never crashes on headless servers.
"""
# ---------------------------------------------------------------------------

def c(text, color):
    """Wrap text in a colorama color code if available."""
    if not COLORAMA_AVAILABLE:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def color_red(text):    return c(text, Fore.RED)
def color_green(text):  return c(text, Fore.GREEN)
def color_cyan(text):   return c(text, Fore.CYAN)
def color_yellow(text): return c(text, Fore.YELLOW)
def color_magenta(text):return c(text, Fore.MAGENTA)
def color_bold(text):
    if COLORAMA_AVAILABLE:
        return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"
    return text


def enforce_txt_extension(name: str) -> str:
    """
    Always save as .txt regardless of what the user typed.
    - 'results'    -> 'results.txt'
    - 'data.log'   -> 'data.txt'
    - 'out.txt'    -> 'out.txt'  (unchanged)
    """
    return str(Path(name.strip()).with_suffix('.txt'))


# ---------------------------------------------------------------------------
# Domain -> friendly service name mapping

"""
DESCRIPTION:
This section is responsible for keeping a dictionary mapping of standard domain names 
to human-readable brand names (e.g., 'netflix.com' -> 'Netflix'). This allows the tool
to group findings cleanly at the end of the scan under beautiful capitalized headers
instead of just dumping raw URLs.
"""
# ---------------------------------------------------------------------------

SERVICE_NAMES = {
    "paypal":    "PayPal",
    "facebook":  "Facebook",
    "instagram": "Instagram",
    "google":    "Google",
    "gmail":     "Gmail",
    "yahoo":     "Yahoo",
    "twitter":   "Twitter",
    "x":         "X (Twitter)",
    "amazon":    "Amazon",
    "netflix":   "Netflix",
    "microsoft": "Microsoft",
    "apple":     "Apple",
    "spotify":   "Spotify",
    "linkedin":  "LinkedIn",
    "reddit":    "Reddit",
    "twitch":    "Twitch",
    "discord":   "Discord",
    "steam":     "Steam",
    "ebay":      "eBay",
    "tiktok":    "TikTok",
    "snapchat":  "Snapchat",
    "pinterest": "Pinterest",
    "tumblr":    "Tumblr",
    "dropbox":   "Dropbox",
    "github":    "GitHub",
    "gitlab":    "GitLab",
    "bitbucket": "Bitbucket",
    "wordpress": "WordPress",
    "shopify":   "Shopify",
    "airbnb":    "Airbnb",
    "uber":      "Uber",
    "lyft":      "Lyft",
    "booking":   "Booking.com",
    "tripadvisor":"TripAdvisor",
    "roblox":    "Roblox",
    "epicgames": "Epic Games",
    "origin":    "Origin (EA)",
    "battlenet": "Battle.net",
    "ubisoft":   "Ubisoft",
    "crunchyroll":"Crunchyroll",
    "hulu":      "Hulu",
    "disneyplus":"Disney+",
    "hbomax":    "HBO Max",
}


def extract_service_name(url: str) -> str:
    """
    Extract a human-readable service name from a URL.
    Falls back to the raw domain if not in the lookup table.
    """
    url_clean = re.sub(r'^https?://', '', url, flags=re.IGNORECASE)
    domain_part = url_clean.split('/')[0].lower()
    domain_part = re.sub(r'^www\.', '', domain_part)
    keyword = domain_part.split('.')[0]
    return SERVICE_NAMES.get(keyword, keyword.capitalize())


# ---------------------------------------------------------------------------
# Core parsing & matching

"""
DESCRIPTION:
This is the heavy lifting section of the script. It contains the primary logic for taking
raw unstructured string lines from text files, splitting them by colons correctly even
when the URL itself contains 'http://', and normalizing URLs (stripping www. and http://)
so they can strictly match the user's base domain queries uniformly.
"""
# ---------------------------------------------------------------------------

def parse_line(line: str):
    """
    Parse a single line formatted as URL:LOGIN:PASSWORD.
    Returns (url, login, password) tuple or None if malformed.

    Handles URLs that include a protocol (http:// / https://) by
    temporarily swapping '://' with a placeholder before splitting,
    so the full URL is always captured as one field.
    """
    line = line.strip()
    if not line:
        return None

    _PROTO_PH = '\x00'
    working = re.sub(r'://', _PROTO_PH, line, count=1)

    parts = working.split(':', 2)
    if len(parts) < 3:
        return None

    url      = parts[0].replace(_PROTO_PH, '://').strip()
    login    = parts[1].replace(_PROTO_PH, '://').strip()
    password = parts[2].replace(_PROTO_PH, '://').strip()

    if not is_valid_line(url, login, password):
        return None

    return url, login, password


def is_valid_line(url: str, login: str, password: str) -> bool:
    """
    Data Cleaning / Validation:
    - Missing or empty fields are rejected.
    """
    if not url or not login or not password:
        return False
    return True


def normalize_url(url: str) -> str:
    """
    Strip protocol and www. prefix so comparisons are prefix-agnostic.
    Examples:
        https://www.g2g.com/login  ->  g2g.com/login
        http://g2g.com/signup      ->  g2g.com/signup
        www.g2g.com                ->  g2g.com
        g2g.com                    ->  g2g.com
    """
    url = url.lower().strip()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url


def extract_base_domain(url: str) -> str:
    """
    Return the base domain (e.g. 'g2g.com') from a normalized URL.
    Handles subdomains by keeping only the last two labels.
    """
    norm = normalize_url(url)
    host = norm.split('/')[0].split('?')[0].split('#')[0]
    host = host.split(':')[0]
    parts = host.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def match_url(url: str, query: str, exact: bool) -> bool:
    """
    Check if a URL from the data file matches the user's query.
    Both sides are normalized before comparison.

    Modes:
        exact=False  -> normalized_query in normalized_url  (substring)
        exact=True   -> base domain of query == base domain of url
    """
    norm_url   = normalize_url(url)
    norm_query = normalize_url(query)

    if exact:
        return extract_base_domain(url) == extract_base_domain(query)
    else:
        return norm_query in norm_url


# ---------------------------------------------------------------------------
# Feature: Multi-keyword parsing

"""
DESCRIPTION:
This module empowers the user to search thousands of lines for multiple targets simultaneously.
It splits the user-provided "comma-separated" query into an array of search tokens, trims
whitespace, and optionally maintains letter casing for strict Regex patterns.
"""
# ---------------------------------------------------------------------------

def parse_keywords(raw: str, is_regex: bool = False) -> list:
    """
    Split a comma-separated keyword string into a cleaned list.
    If is_regex=True, case is preserved. Otherwise lowercase.
    """
    if is_regex:
        return [k.strip() for k in raw.split(',') if k.strip()]
    return [k.strip().lower() for k in raw.split(',') if k.strip()]


# ---------------------------------------------------------------------------
# Feature: Search type filter

"""
DESCRIPTION:
One of the most powerful features of CredFinder: determining *where* the keyword must match.
Instead of searching the entire line blindly, this section parses through 'URL', 'Email',
'Username', 'Password', and standard exact string modes to guarantee 100% precision.
It also includes the 'Regex (Advanced)' matching engine for compiling complex query logic.
"""
# ---------------------------------------------------------------------------

def match_by_type(url: str, login: str, password: str, keywords: list,
                  exact: bool, search_type: str) -> bool:
    """
    Return True if the record matches ANY keyword under the given search type.

    search_type values:
        'URL'               -> match only the URL field
        'Email'             -> match login if it contains '@'
        'Username'          -> match login if it does NOT contain '@'
        'Password'          -> match only password field
        'All'               -> match URL or login
        'Regex (Advanced)'  -> keywords are compiled re.Pattern objects; search full line
    """
    if search_type == 'Regex (Advanced)':
        full_line = f"{url}:{login}:{password}"
        for pattern in keywords:
            if pattern.search(full_line):
                return True
        return False

    for kw in keywords:
        if search_type == 'URL':
            if match_url(url, kw, exact):
                return True

        elif search_type == 'Email':
            if '@' in login and kw in login.lower():
                return True

        elif search_type == 'Username':
            if '@' not in login and kw in login.lower():
                return True

        elif search_type == 'Password':
            if kw in password.lower():
                return True

        else:  # 'All'
            if match_url(url, kw, exact):
                return True
            if kw in login.lower():
                return True

    return False


# ---------------------------------------------------------------------------
# Feature: Fuzzy matching fallback

"""
DESCRIPTION:
If a user's standard search returns absolutely ZERO results, this section is invoked as a 
fail-safe. Using Python's built-in difflib sequence matcher, it mathematically checks for 
near-miss misspellings (e.g., searching 'facebook' might catch 'facebok') so no leaked 
credential goes unfound due to a typo in the original database leak.
"""
# ---------------------------------------------------------------------------

def fuzzy_match(url: str, keywords: list, threshold: float = 0.6) -> bool:
    """
    Use difflib to fuzzy-match any keyword against the base domain of a URL.
    Only called when the normal search returns 0 results.
    threshold: 0.0 (anything) to 1.0 (identical). 0.6 is a sensible default.
    """
    domain = extract_base_domain(url)
    for kw in keywords:
        norm_kw = normalize_url(kw)
        ratio = difflib.SequenceMatcher(None, norm_kw, domain).ratio()
        if ratio >= threshold:
            return True
    return False


# ---------------------------------------------------------------------------
# Feature: History (recent searches)

"""
DESCRIPTION:
This handles the creation and loading of 'history.json'. It essentially allows the Interactive
Menu to remember the last 5 queries the user ran, operating exactly like your web browser's search
history, providing instant access out-of-the-box without needing to retype long domains.
"""
# ---------------------------------------------------------------------------

HISTORY_FILE = Path(__file__).parent / "history.json"
MAX_HISTORY  = 5


def load_history() -> list:
    """Load the last N searches from history.json. Returns [] on any error."""
    try:
        if HISTORY_FILE.exists():
            data = json.loads(HISTORY_FILE.read_text(encoding='utf-8'))
            if isinstance(data, list):
                return data[:MAX_HISTORY]
    except Exception:
        pass
    return []


def save_history(query_raw: str) -> None:
    """Prepend query to history, keep only last MAX_HISTORY entries."""
    history = load_history()
    # Remove duplicate if present, prepend new entry
    history = [h for h in history if h != query_raw]
    history.insert(0, query_raw)
    history = history[:MAX_HISTORY]
    try:
        HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding='utf-8')
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Feature: Auto-detect latest .txt file

"""
DESCRIPTION:
Presents quality-of-life logic that checks the current working directory for the most 
recently modified .txt file. When launching the script, it prompts the user to scan this file 
automatically, saving them from having to open a folder dialog or typing file names manually.
"""
# ---------------------------------------------------------------------------

def get_latest_file(directory: str = ".") -> str | None:
    """
    Return the path of the most recently modified .txt file in `directory`.
    Returns None if no .txt files exist there.
    """
    candidates = list(Path(directory).glob("*.txt"))
    if not candidates:
        return None
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    return str(latest.resolve())


# ---------------------------------------------------------------------------
# Output formatting

"""
DESCRIPTION:
This section governs how text is physically printed and structured. Whether pushing out immediate
line-by-line CLI output or consolidating hundreds of tuple hits into cleanly separated blocks
(i.e. '----PayPal----'), this area strictly guards how data is viewed via terminal or .txt save.
"""
# ---------------------------------------------------------------------------

def format_output(url: str, login: str, password: str, original_line: str) -> str:
    """
    Format a single credential match into the display block.
    Returns a plain-text string (color codes handled separately for terminal).
    """
    service = extract_service_name(url)
    return (
        f"------{service}--------\n"
        f"URL      : {url}\n"
        f"Login    : {login}\n"
        f"Password : {password}\n"
        f"Full     : {original_line.strip()}\n"
        f"---------------------------"
    )


def print_match(url: str, login: str, password: str, original_line: str):
    """Print a formatted match block to terminal with colors."""
    service = extract_service_name(url)
    print(color_cyan(f"\n------{color_bold(service)}--------"))
    print(f"{color_yellow('URL     ')} : {color_green(url)}")
    print(f"{color_yellow('Login   ')} : {color_magenta(login)}")
    print(f"{color_yellow('Password')} : {color_red(password)}")
    print(f"{color_yellow('Full    ')} : {original_line.strip()}")
    print(color_cyan("---------------------------"))


# ---------------------------------------------------------------------------
# Feature: Group results by domain

"""
DESCRIPTION:
Analyzes the final collected payload from the scanning loops and groups items by their base domains.
It uses the friendly service name mappings from earlier to create structured dict clusters.
"""
# ---------------------------------------------------------------------------

def group_results(records: list) -> dict:
    """
    Group a list of (url, login, password, raw_line) tuples by base domain.
    Returns an ordered dict: { domain: [(url, login, password, raw_line), ...] }
    """
    groups = defaultdict(list)
    for record in records:
        url = record[0]
        domain = extract_base_domain(url)
        groups[domain].append(record)
    return dict(groups)


def print_grouped(records: list) -> None:
    """
    Print all matched records grouped by their base domain.
    Each group shows a header with the domain name and count.
    """
    groups = group_results(records)
    for domain, items in groups.items():
        service = extract_service_name(domain)
        count   = len(items)
        print(color_bold(f"\n  [{service} - {domain}]  ({count} result{'s' if count != 1 else ''})"))
        print(color_cyan("  " + "-" * 43))
        for url, login, password, raw_line in items:
            print_match(url, login, password, raw_line)


def format_grouped_output(records: list) -> list:
    """
    Produce plain-text formatted lines for the output file, grouped by domain.
    """
    groups  = group_results(records)
    lines   = []
    for domain, items in groups.items():
        service = extract_service_name(domain)
        count   = len(items)
        lines.append(f"\n[{service} - {domain}] ({count} result{'s' if count != 1 else ''})\n")
        lines.append("-" * 45 + "\n")
        for url, login, password, raw_line in items:
            lines.append(format_output(url, login, password, raw_line) + "\n")
    return lines


# ---------------------------------------------------------------------------
# File scanning  (extended to support multi-keyword + search type + grouping)

"""
DESCRIPTION:
The master streaming loop. This function opens your gigabyte-level target files and streams them 
one line at a time to prevent RAM overload. It directly calls the line parsers, matchers, and 
tracks the live Progress Bar using tqdm if available, keeping counts of skipped malformed lines.
"""
# ---------------------------------------------------------------------------

def scan_file(filepath: str, keywords: list, exact: bool, verbose: bool,
              output_lines: list, search_type: str = 'URL',
              collected: list = None) -> tuple:
    """
    Stream-scan a single file for credential matches.

    Parameters:
        keywords     : list of normalized keyword strings
        exact        : exact domain match if True
        verbose      : show skipped line count
        output_lines : collector list for file-save output (or None)
        search_type  : 'URL' | 'Email' | 'Username' | 'All'
        collected    : if provided, append (url, login, password, raw_line) tuples here
                       (used for grouped display)

    Returns:
        (lines_scanned, matches_found, lines_skipped)
    """
    lines_scanned = 0
    matches_found = 0
    lines_skipped = 0
    PROGRESS_EVERY = 1000   # print live counter every N lines without tqdm

    try:
        file_size = os.path.getsize(filepath)
    except OSError:
        file_size = 0

    print(color_bold(f"\n  Scanning: {filepath}"))

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            if TQDM_AVAILABLE and file_size > 0:
                iterator = tqdm(
                    f,
                    desc=color_yellow("  Progress"),
                    unit=" lines",
                    dynamic_ncols=True,
                    leave=False
                )
            else:
                iterator = f

            for raw_line in iterator:
                lines_scanned += 1

                # Feature 5: live progress counter (when tqdm is not active)
                if not TQDM_AVAILABLE and lines_scanned % PROGRESS_EVERY == 0:
                    print(
                        color_yellow(f"  Scanning: {lines_scanned:,} lines..."),
                        end='\r', flush=True
                    )

                parsed = parse_line(raw_line)
                if parsed is None:
                    lines_skipped += 1
                    continue

                url, login, password = parsed

                if match_by_type(url, login, password, keywords, exact, search_type):
                    matches_found += 1

                    # Collect tuple for grouping (interactive mode)
                    if collected is not None:
                        collected.append((url, login, password, raw_line))
                    else:
                        # Fallback: print immediately (CLI mode / no grouping)
                        print_match(url, login, password, raw_line)

                    # Collect plain-text version for file output
                    if output_lines is not None:
                        block = format_output(url, login, password, raw_line)
                        output_lines.append(block + "\n")

    except PermissionError:
        print(color_red(f"  Permission denied: {filepath}"))
    except FileNotFoundError:
        print(color_red(f"  File not found: {filepath}"))
    except KeyboardInterrupt:
        print(color_yellow("\nScan interrupted by user (Ctrl+C)."))
        raise

    # Clear the progress line if we used the plain counter
    if not TQDM_AVAILABLE and lines_scanned > 0:
        print(' ' * 60, end='\r')

    if verbose:
        print(color_yellow(f"  Skipped invalid lines: {lines_skipped}"))

    return lines_scanned, matches_found, lines_skipped


# ---------------------------------------------------------------------------
# Entry point

"""
DESCRIPTION:
Extremely simple startup function. Detects whether system arguments exist. If they do, it instantly
launches CLI mode for automation. If the script is single-clicked or double-clicked, it detects 
zero arguments and boots up the gorgeous Interactive GUI flow natively.
"""

"""
DESCRIPTION:
This handles automated execution from the command prompt using argparse. It sets up all available
flag switches (-q, -d, -f, -t) so advanced users can pipe or wrap CredFinder inside overarching
automated scripting environments without ever needing GUI interaction.
"""
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credfinder",
        description=(
            "CredFinder - search credential files (URL:LOGIN:PASSWORD) "
            "by domain query."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--query", "-q",
        required=False,
        help="Keyword(s) to search, comma-separated (e.g. paypal,g2g)"
    )
    parser.add_argument(
        "--file", "-f",
        metavar="FILE",
        help="Path to a single TXT file to scan"
    )
    parser.add_argument(
        "--dir", "-d",
        metavar="DIR",
        help="Directory path - recursively scans all .txt files inside"
    )
    parser.add_argument(
        "--output", "-o",
        metavar="OUTPUT",
        help="Save results to this file path"
    )
    parser.add_argument(
        "--type", "-t",
        choices=["URL", "Email", "Username", "Password", "All", "Regex"],
        default="URL",
        help="Target field or search type (default: URL)"
    )
    parser.add_argument(
        "--exact",
        action="store_true",
        help="Exact domain match instead of partial substring match"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show skipped (malformed) line counts per file"
    )
    return parser


def collect_files(args) -> list:
    """
    Determine which files to scan based on CLI arguments (--file / --dir).
    Interactive mode has its own path-collection logic.
    """
    files = []

    if args.file:
        p = Path(args.file)
        if not p.is_file():
            print(color_red(f"Error: '{args.file}' is not a valid file."))
            sys.exit(1)
        files.append(str(p.resolve()))

    elif args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            print(color_red(f"Error: '{args.dir}' is not a valid directory."))
            sys.exit(1)
        found = sorted(d.rglob("*.txt"))
        if not found:
            print(color_yellow(f"No .txt files found in '{args.dir}'."))
            sys.exit(0)
        files = [str(p.resolve()) for p in found]

    else:
        print(color_red("Error: supply --file or --dir when using CLI mode."))
        sys.exit(1)

    return files


def print_banner():
    banner = r"""
  ____              _ _____ _           _
 / ___|_ __ ___  __| |  ___(_)_ __   __| | ___ _ __
| |   | '__/ _ \/ _` | |_  | | '_ \ / _` |/ _ \ '__|
| |___| | |  __/ (_| |  _| | | | | | (_| |  __/ |
 \____|_|  \___|\__,_|_|   |_|_| |_|\__,_|\___|_|
"""
    print(color_cyan(banner))
    print(color_bold("  Fast credential searcher for URL:LOGIN:PASSWORD files\n"))


# ---------------------------------------------------------------------------
# Interactive mode helpers

"""
DESCRIPTION:
This section wraps the 'questionary' terminal GUI library. It creates highly robust prompt requests
complete with custom aesthetics, and automatically falls back to native OS features (like Tkinter
file selection dialogs) for file and folder browsing without breaking terminal immersion.
"""
# ---------------------------------------------------------------------------

_Q_STYLE = None
if QUESTIONARY_AVAILABLE:
    _Q_STYLE = QStyle([
        ("qmark",        "fg:#00bcd4 bold"),
        ("question",     "bold"),
        ("answer",       "fg:#00e676 bold"),
        ("pointer",      "fg:#00bcd4 bold"),
        ("highlighted",  "fg:#00bcd4 bold"),
        ("selected",     "fg:#00e676"),
        ("separator",    "fg:#cc5454"),
        ("instruction",  "fg:#ffeb3b"),
        ("text",         ""),
        ("disabled",     "fg:#858585 italic"),
    ])


def _ask(prompt_fn, *args, **kwargs):
    """
    Thin wrapper around a questionary prompt call.
    Returns None if the user pressed Ctrl+C / Ctrl+D.
    """
    try:
        kwargs["style"] = _Q_STYLE
        return prompt_fn(*args, **kwargs).ask()
    except (KeyboardInterrupt, EOFError):
        return None


def _prompt_valid_file() -> str | None:
    """Keep asking for a file path until a valid one is entered, or user cancels."""
    if TKINTER_AVAILABLE:
        print(color_cyan("  Opening file select dialog..."))
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path_str = filedialog.askopenfilename(
            title="Select a credential file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        root.destroy()
        
        if not path_str:
            return None
        p = Path(path_str)
        if p.is_file():
            return str(p.resolve())
        print(color_red(f"  Error: not a valid file: '{path_str}'."))
        return None

    # Fallback to questionary
    while True:
        path_str = _ask(questionary.path, "Enter file path:")
        if path_str is None:
            return None
        p = Path(path_str.strip().strip('"').strip("'"))
        if p.is_file():
            return str(p.resolve())
        print(color_red(f"  Error: not a valid file: '{path_str}'. Please try again."))


def _prompt_valid_dir() -> list | None:
    """Keep asking for a directory until .txt files are found, or user cancels."""
    if TKINTER_AVAILABLE:
        print(color_cyan("  Opening folder select dialog..."))
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path_str = filedialog.askdirectory(title="Select folder to scan")
        root.destroy()
        
        if not path_str:
            return None
        d = Path(path_str)
        if not d.is_dir():
            print(color_red(f"  Error: not a valid directory: '{path_str}'."))
            return None
        found = sorted(d.rglob("*.txt"))
        if not found:
            print(color_yellow(f"  Warning: no .txt files found in '{path_str}'. Returning to menu."))
            return None
        return [str(p.resolve()) for p in found]

    # Fallback to questionary
    while True:
        path_str = _ask(questionary.path, "Enter folder path:")
        if path_str is None:
            return None
        d = Path(path_str.strip().strip('"').strip("'"))
        if not d.is_dir():
            print(color_red(f"  Error: not a valid directory: '{path_str}'. Please try again."))
            continue
        found = sorted(d.rglob("*.txt"))
        if not found:
            print(color_yellow(f"  Warning: no .txt files found in '{path_str}'. Try another folder."))
            continue
        return [str(p.resolve()) for p in found]


def show_post_results_menu(query_raw: str, exact: bool,
                           total_matches: int, output_lines: list, records: list = None) -> str:
    """
    Show the post-scan action menu.
    Returns one of: 'save', 'menu', 'exit'
    """
    while True:
        choices = ["Save results to file"]
        if records:
            choices.append("View results in terminal")
        choices.extend(["Return to main menu", "Exit"])

        choice = _ask(questionary.select,
                      "What would you like to do next? (Use arrow keys)",
                      choices=choices)
        
        if choice is None or choice == "Exit":
            return "exit"
        
        if choice == "Return to main menu":
            return "menu"
        
        if choice == "View results in terminal":
            if len(records) > 50:
                print(color_yellow(f"\n  [!] Printing {len(records)} results might lag the terminal."))
                confirm = _ask(questionary.confirm, "Are you sure you want to print all?", default=False)
                if not confirm:
                    continue
            print_grouped(records)
            print()
            continue

        if choice == "Save results to file":
            # --- Save results ---
            if not output_lines:
                print(color_yellow("  Warning: no matches to save."))
                continue

            fname_raw = _ask(questionary.text, "Enter output filename (extension forced to .txt):")
            if not fname_raw:
                print(color_yellow("  Warning: no filename given. Skipping save."))
                continue

            filename = enforce_txt_extension(fname_raw)
            try:
                with open(filename, 'w', encoding='utf-8') as out_f:
                    header = (
                        f"CredFinder Results\n"
                        f"Query   : {query_raw}\n"
                        f"Mode    : {'Exact' if exact else 'Partial'}\n"
                        f"Matches : {total_matches}\n"
                        f"{'=' * 45}\n\n"
                    )
                    out_f.write(header)
                    out_f.writelines(output_lines)
                print(color_green(f"\nResults saved to: {filename}"))
                return "menu"
            except IOError as e:
                print(color_red(f"\nCould not write file: {e}"))
                continue


def show_main_menu() -> str:
    """
    Display the top-level arrow-key navigation menu.
    Returns 'file', 'dir', or 'exit'.
    """
    choices = ["Search in a single file", "Search in a folder", "Exit"]
    choice = _ask(questionary.select,
                  "What would you like to do?",
                  choices=choices)
    if choice is None or choice == "Exit":
        return "exit"
    if choice == "Search in a single file":
        return "file"
    return "dir"


# ---------------------------------------------------------------------------
# Feature: Interactive file picker with auto-detect

"""
DESCRIPTION:
Unifies the file picker system in interactive mode. If a latest file is detected, it asks the user 
if they want to scan it; otherwise it delegates to the manual Tkinter file selection menu.
"""
# ---------------------------------------------------------------------------

def pick_files_interactively() -> list | None:
    """
    Show a menu:
      > Use latest modified file
        Choose file manually
        Scan folder
    Returns a list of file paths, or None if user cancelled.
    """
    latest = get_latest_file(".")

    choices = []
    if latest:
        choices.append(f"Use latest file  [{Path(latest).name}]")
    choices += ["Choose file manually", "Scan folder"]

    choice = _ask(questionary.select, "Select file source:", choices=choices)
    if choice is None:
        return None

    if choice.startswith("Use latest file"):
        return [latest]
    elif choice == "Choose file manually":
        path = _prompt_valid_file()
        return [path] if path else None
    else:  # Scan folder
        return _prompt_valid_dir()


# ---------------------------------------------------------------------------
# Feature: Keyword entry with history

"""
DESCRIPTION:
Unifies the search history interface for the Interactive menu. Offers previous searches natively via
arrow keys or requests a completely new custom query from the user.
"""
# ---------------------------------------------------------------------------

def pick_keyword_interactively() -> str | None:
    """
    Show recent searches at the top of the keyword prompt.
    Returns the chosen raw query string, or None if cancelled.
    """
    history = load_history()

    if history:
        history_choices = history + ["-- New search --"]
        choice = _ask(
            questionary.select,
            "Recent searches (or start a new one):",
            choices=history_choices,
        )
        if choice is None:
            return None
        if choice != "-- New search --":
            return choice   # reuse history entry directly

    # New keyword entry
    raw = _ask(questionary.text, "Enter keyword(s) to search (comma-separated):")
    return raw


# ---------------------------------------------------------------------------
# Interactive mode main loop

"""
DESCRIPTION:
This is the primary infinite 'while True' loop that keeps the program alive. It strings together
all the isolated features above: presenting the main menu, calling file collection logic,
gathering keywords, showing the progress bar through the search scan, and presenting the 
cleanly formatted exit/summary panel upon completion.
"""
# ---------------------------------------------------------------------------

def run_interactive_mode():
    """
    Full interactive loop: main menu -> collect inputs -> scan -> post-results.
    Loops back to main menu until user chooses Exit.
    """
    if not QUESTIONARY_AVAILABLE:
        print(color_red(
            "Error: 'questionary' is not installed.\n"
            "   Run: pip install questionary"
        ))
        sys.exit(1)

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print_banner()

        # -- Main menu action -----------------------------------------------
        action = show_main_menu()
        if action == "exit":
            print(color_cyan("\nGoodbye!\n"))
            sys.exit(0)

        # -- File / folder source -------------------------------------------
        if action == "file":
            files = pick_files_interactively()
        else:
            files = _prompt_valid_dir()

        if not files:
            continue

        # -- Keyword(s) with history ----------------------------------------
        query_raw = pick_keyword_interactively()
        if query_raw is None:
            continue
        query_raw = query_raw.strip()
        if not query_raw:
            print(color_yellow("  Warning: empty keyword - returning to menu."))
            input("  Press Enter to continue...")
            continue

        save_history(query_raw)

        # -- Search type ----------------------------------------------------
        search_type_choice = _ask(
            questionary.select,
            "Search in:",
            choices=["URL", "Email", "Username", "Password", "All", "Regex (Advanced)"],
        )
        if search_type_choice is None:
            continue
        search_type = search_type_choice

        # -- Parse Keywords and Validate Regex ------------------------------
        if search_type == "Regex (Advanced)":
            raw_keywords = parse_keywords(query_raw, is_regex=True)
            patterns = []
            valid = True
            for kw in raw_keywords:
                try:
                    patterns.append(re.compile(kw, re.IGNORECASE))
                except re.error as e:
                    print(color_red(f"  Error: Invalid regex pattern '{kw}': {e}"))
                    valid = False
                    break
            if not valid:
                input("  Press Enter to try again...")
                continue
            keywords = patterns
            exact = False # Exact matching disables for advanced regex
        else:
            keywords = parse_keywords(query_raw, is_regex=False)

            # -- Exact match toggle ---------------------------------------------
            exact_choice = _ask(
                questionary.select,
                "Exact match only?",
                choices=["No", "Yes"],
            )
            if exact_choice is None:
                continue
            exact = (exact_choice == "Yes")

        # -- Run scan -------------------------------------------------------
        output_lines: list  = []
        collected:    list  = []   # gathers (url, login, password, raw_line) for grouping
        total_files = total_lines = total_matches = total_skipped = 0
        fuzzy_used  = False

        if search_type == "Regex (Advanced)":
            kw_print = [p.pattern for p in keywords]
            mode_print = "Regex match"
        else:
            kw_print = keywords
            mode_print = 'Exact domain' if exact else 'Partial match'

        print(color_bold(f"\n  Keywords : {color_cyan(', '.join(kw_print))}"))
        print(color_bold(f"  Mode     : {mode_print}"))
        print(color_bold(f"  Type     : {search_type}"))
        print(color_bold(f"  Files    : {len(files)} file(s) to scan\n"))

        try:
            for filepath in files:
                total_files += 1
                lines, matches, skipped = scan_file(
                    filepath, keywords, exact,
                    verbose=True, output_lines=output_lines,
                    search_type=search_type, collected=collected
                )
                total_lines   += lines
                total_matches += matches
                total_skipped += skipped
        except KeyboardInterrupt:
            print(color_yellow("\nScan interrupted."))

        # -- Fuzzy fallback if zero normal matches --------------------------
        if total_matches == 0 and search_type in ('URL', 'All'):
            print(color_yellow("\n  No normal matches. Trying fuzzy search..."))
            fuzzy_hits: list = []
            try:
                for filepath in files:
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
                            for raw_line in fh:
                                parsed = parse_line(raw_line)
                                if parsed is None:
                                    continue
                                url, login, password = parsed
                                if fuzzy_match(url, keywords):
                                    fuzzy_hits.append((url, login, password, raw_line))
                    except (PermissionError, FileNotFoundError):
                        pass
            except KeyboardInterrupt:
                pass

            if fuzzy_hits:
                fuzzy_used  = True
                total_matches += len(fuzzy_hits)
                collected.extend(fuzzy_hits)
                print(color_yellow(
                    f"  Fuzzy search found {len(fuzzy_hits)} possible match(es)."
                ))
            else:
                print(color_yellow("  Fuzzy search also found nothing."))

        # -- Prepare grouped output -----------------------------------------
        if collected:
            # Build grouped output for file-save (no automatic terminal print)
            output_lines = format_grouped_output(collected)

        # -- Summary --------------------------------------------------------
        print(color_bold("\n" + "=" * 45))
        print(color_bold("  SCAN SUMMARY"))
        print(color_bold("=" * 45))
        print(f"  Files scanned  : {color_cyan(str(total_files))}")
        print(f"  Lines scanned  : {color_cyan(str(total_lines))}")
        print(f"  Matches found  : "
              f"{color_green(str(total_matches)) if total_matches > 0 else color_red('0')}")
        print(f"  Lines skipped  : {color_yellow(str(total_skipped))}")
        if fuzzy_used:
            print(color_yellow("  (Fuzzy matching was used)"))
        print(color_bold("=" * 45))

        if total_matches == 0:
            print(color_yellow(
                "\n  No matches found. "
                "Try a broader keyword (e.g. 'g2g' instead of 'www.g2g.com')."
            ))

        # -- Post-results menu ----------------------------------------------
        result = show_post_results_menu(query_raw, exact, total_matches, output_lines, collected)
        if result == "exit":
            print(color_cyan("\nGoodbye!\n"))
            sys.exit(0)
        # result == "menu" -> loop back to main menu automatically


# ---------------------------------------------------------------------------
# CLI mode (original logic, adapted for multi-keyword + search type)

"""
DESCRIPTION:
The non-interactive equivalent to the loop above. It runs exactly once natively using argument
variables. This guarantees automated environments receive immediate success or standard exit codes.
"""
# ---------------------------------------------------------------------------

def run_cli_mode(args):
    """Execute the CLI scan using parsed argparse arguments."""
    if not args.query:
        print(color_red("Error: --query / -q is required in CLI mode."))
        build_parser().print_help()
        sys.exit(1)

    files = collect_files(args)
    search_type = args.type

    if search_type == "Regex":
        search_type = "Regex (Advanced)"
        raw_keywords = parse_keywords(args.query, is_regex=True)
        patterns = []
        for kw in raw_keywords:
            try:
                patterns.append(re.compile(kw, re.IGNORECASE))
            except re.error as e:
                print(color_red(f"Error: Invalid regex pattern '{kw}': {e}"))
                sys.exit(1)
        keywords = patterns
        print(color_bold(f"\n  Patterns : {color_cyan(', '.join([p.pattern for p in keywords]))}"))
        exact = False # Exact domains disabled for Regex
    else:
        keywords = parse_keywords(args.query, is_regex=False)
        exact = args.exact
        print(color_bold(f"\n  Keywords : {color_cyan(', '.join(keywords))}"))

    output_lines = [] if args.output else None

    total_files   = 0
    total_lines   = 0
    total_matches = 0
    total_skipped = 0

    print(color_bold(f"  Mode     : {'Exact domain' if exact else 'Partial match' if search_type != 'Regex (Advanced)' else 'Regex match'}"))
    print(color_bold(f"  Type     : {search_type}"))
    print(color_bold(f"  Files    : {len(files)} file(s) to scan\n"))

    try:
        for filepath in files:
            total_files += 1
            lines, matches, skipped = scan_file(
                filepath, keywords, exact, args.verbose,
                output_lines, search_type=search_type, collected=None
            )
            total_lines   += lines
            total_matches += matches
            total_skipped += skipped

    except KeyboardInterrupt:
        print(color_yellow("\nAborted. Partial results shown above."))

    print(color_bold("\n" + "=" * 45))
    print(color_bold("  SCAN SUMMARY"))
    print(color_bold("=" * 45))
    print(f"  Files scanned  : {color_cyan(str(total_files))}")
    print(f"  Lines scanned  : {color_cyan(str(total_lines))}")
    print(f"  Matches found  : "
          f"{color_green(str(total_matches)) if total_matches > 0 else color_red('0')}")
    if args.verbose:
        print(f"  Lines skipped  : {color_yellow(str(total_skipped))}")
    print(color_bold("=" * 45))

    if total_matches == 0:
        print(color_yellow(
            "\n  No matches found. "
            "Try a broader keyword (e.g. 'g2g' instead of 'www.g2g.com')."
        ))

    if args.output and output_lines:
        save_path = enforce_txt_extension(args.output)
        try:
            with open(save_path, 'w', encoding='utf-8') as out_f:
                header = (
                    f"CredFinder Results\n"
                    f"Query   : {args.query}\n"
                    f"Mode    : {'Exact' if args.exact else 'Partial'}\n"
                    f"Matches : {total_matches}\n"
                    f"{'=' * 45}\n\n"
                )
                out_f.write(header)
                out_f.writelines(output_lines)
            print(color_green(f"\nResults saved to: {save_path}"))
        except IOError as e:
            print(color_red(f"\nCould not write output file: {e}"))
    elif args.output and not output_lines:
        print(color_yellow(f"\nNo matches to save to '{enforce_txt_extension(args.output)}'."))


# ---------------------------------------------------------------------------
# Entry point

"""
DESCRIPTION:
Extremely simple startup function. Detects whether system arguments exist. If they do, it instantly
launches CLI mode for automation. If the script is single-clicked or double-clicked, it detects 
zero arguments and boots up the gorgeous Interactive GUI flow natively.
"""
# ---------------------------------------------------------------------------

def main():
    print_banner()

    parser = build_parser()

    if len(sys.argv) > 1:
        args = parser.parse_args()
        try:
            run_cli_mode(args)
        except KeyboardInterrupt:
            print(color_yellow("\nInterrupted."))
            sys.exit(0)
    else:
        try:
            run_interactive_mode()
        except KeyboardInterrupt:
            print(color_cyan("\nGoodbye!\n"))
            sys.exit(0)


if __name__ == "__main__":
    main()
