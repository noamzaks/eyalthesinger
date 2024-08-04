"""Crack a given cipher"""

import multiprocessing as mp
import os
import subprocess
import time
from typing import List

import click
from halo import Halo


@click.command()
@click.argument("cipher")
@click.argument("wordlist")
@click.argument("hash")
@click.option(
    "-j",
    "--jobs",
    default=0,
    help="Number of cracking subprocesses, defaults to CPU count.",
)
def crack(cipher: str, wordlist: str, hash: str, jobs: int):
    if jobs == 0:
        jobs = mp.cpu_count()
        print(f"Using {jobs} jobs according to the CPU count.")

    spinner = Halo(text=f"Splitting '{wordlist}' to {jobs} jobs...")
    spinner.start()
    start = time.time()

    with open(wordlist, "rb") as f:
        lines = f.read().split(b"\n")

    process_line_counts = len(lines) // jobs + 1

    processes: List[subprocess.Popen] = []
    for thread_number in range(jobs):
        wordlist_name = f"wordlist{thread_number}.txt"
        with open(wordlist_name, "wb") as f:
            f.write(
                b"\n".join(
                    lines[
                        process_line_counts * thread_number : process_line_counts
                        * (thread_number + 1)
                    ]
                )
                + b"\n"
            )

    preprocessing_end = time.time()

    for thread_number in range(jobs):
        wordlist_name = f"wordlist{thread_number}.txt"
        with open(wordlist_name, "r") as f:
            processes.append(
                subprocess.Popen(
                    ["./sing", cipher] + hash.split(":"),
                    stdin=f,
                    stdout=subprocess.PIPE,
                )
            )

    spinner.text = f"Cracking {cipher}..."

    for _ in processes:
        os.wait()
        for process in processes:
            if (
                process.poll() == 0
                and len(output := process.stdout.read().strip()) != 0
            ):
                end = time.time()
                spinner.succeed(
                    f"Finished in {end - start :.2f}s ({end - preprocessing_end :.2f}s without preprocessing)."
                )
                print(f"Found password {output}.")
                for process in processes:
                    process.kill()
                return

    spinner.fail(f"Couldn't crack {cipher} in '{wordlist}'.")
