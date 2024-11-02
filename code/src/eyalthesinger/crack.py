"""Crack a given cipher"""

import asyncio
import multiprocessing as mp
import subprocess
import time
from typing import List

import click
from halo import Halo


async def run_crack(cipher: str, wordlist: str, hash: str, jobs: int):
    if jobs == 0:
        jobs = mp.cpu_count()
        print(f"Using {jobs} jobs according to the CPU count.")

    spinner = Halo(text=f"Splitting '{wordlist}' to {jobs} jobs...")
    spinner.start()
    start = time.time()

    with open(wordlist, "rb") as f:
        lines = f.read().split(b"\n")

    process_line_counts = len(lines) // jobs + 1

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

    processes: List[asyncio.subprocess.Process] = []
    for thread_number in range(jobs):
        wordlist_name = f"wordlist{thread_number}.txt"
        with open(wordlist_name, "r") as f:
            process = await asyncio.create_subprocess_exec(
                "./sing", cipher, *hash.split(":"), stdin=f, stdout=subprocess.PIPE
            )
            processes.append(process)

    spinner.text = f"Cracking {cipher}..."

    pending_list = [asyncio.create_task(p.wait()) for p in processes]
    pending = pending_list
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

        for d in done:
            process = processes[pending_list.index(d)]

            if process.returncode != 0:
                continue

            output = await process.stdout.read()
            output = output.strip()
            if len(output) == 0:
                continue

            end = time.time()
            spinner.succeed(
                f"Finished in {end - start :.2f}s ({end - preprocessing_end :.2f}s without preprocessing)."
            )
            print(f"Found password {output}.")
            for process in processes:
                try:
                    process.kill()
                except Exception:
                    pass
            return

    end = time.time()
    spinner.fail(
        f"Couldn't crack {cipher} in '{wordlist}' (took {end - start :.2f}s, {end - preprocessing_end :.2f}s without preprocessing)."
    )


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
    asyncio.get_event_loop().run_until_complete(run_crack(cipher, wordlist, hash, jobs))
