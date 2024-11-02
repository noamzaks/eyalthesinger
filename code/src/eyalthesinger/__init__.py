import logging

import click


@click.group()
def cli():
    pass


def main() -> int:
    logging.getLogger("scapy").setLevel(logging.CRITICAL)

    from eyalthesinger.crack import crack
    from eyalthesinger.download import download
    from eyalthesinger.format import format
    from eyalthesinger.pad import pad
    from eyalthesinger.connect import connect
    from eyalthesinger.server import server

    cli.add_command(download)
    cli.add_command(crack)
    cli.add_command(format)
    cli.add_command(pad)
    cli.add_command(connect)
    cli.add_command(server)
    cli()

    return 0
