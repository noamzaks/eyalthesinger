"""Download a wordlist"""

import click

from eyalthesinger.utilities import download_url

KNOWN_WORDLISTS = {
    "rockyou": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
}


@click.command()
@click.argument("wordlist")
def download(wordlist: str):
    url = wordlist
    if not wordlist.startswith("https://") and not wordlist.startswith("http://"):
        wordlist = wordlist.lower()
        if wordlist not in KNOWN_WORDLISTS:
            raise Exception(
                f"Given wordlist is not a valid URL nor a known wordlist ({', '.join(KNOWN_WORDLISTS.keys())})"
            )
        url = KNOWN_WORDLISTS[wordlist]

    download_url(url)
