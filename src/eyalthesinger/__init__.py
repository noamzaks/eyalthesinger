import click

from eyalthesinger.download import download


@click.group()
def cli():
    pass


def main() -> int:
    cli.add_command(download)
    cli()

    return 0
