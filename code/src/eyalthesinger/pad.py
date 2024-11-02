"""Download a wordlist"""

import click


@click.command()
@click.argument("input")
@click.argument("output")
def pad(input: str, output: str):
    # read file
    with open(input, "rb") as f:
        contents = f.read().split(b"\n")

    # calculate max password length
    max_password_length = max([len(line) for line in contents])
    print("The padded password length is", max_password_length)

    # pad lines
    contents = [pad_word(line, max_password_length) for line in contents]
    # write file
    with open(output, "wb") as f:
        f.write(b"\n".join(contents))


def pad_word(word: bytes, target_length: int, pad_char=b"\0"):
    if len(word) < target_length:
        word = word + pad_char * (target_length - len(word))

    return word
