import click

from eyalthesinger.crack import crack
from eyalthesinger.download import download


@click.group()
def cli():
    pass


def main() -> int:
    cli.add_command(download)
    cli.add_command(crack)
    cli()

    return 0
