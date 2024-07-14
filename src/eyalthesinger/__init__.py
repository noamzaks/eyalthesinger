import logging

import click

from eyalthesinger.crack import crack
from eyalthesinger.download import download


@click.group()
def cli():
    pass


def main() -> int:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    cli.add_command(download)
    cli.add_command(crack)
    cli()

    return 0
    return 0
