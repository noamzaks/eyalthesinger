import os
import subprocess
import time
from typing import Optional

SAMPLES = 1


def measure_command(command: str, program: str, stdin: Optional[str] = None):
    for _ in range(SAMPLES):
        stdin_file = None
        if stdin is not None:
            stdin_file = open(stdin, "r")

        start = time.time()
        p = subprocess.Popen(
            command.split(" "),
            stdin=stdin_file,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        p.wait()
        end = time.time()
        print(f"{program}: {end - start :.2f}s (exit code: {p.returncode})")

        if stdin is not None:
            stdin_file.close()


if __name__ == "__main__":
    os.environ["OMP_NUM_THREADS"] = "1"

    print("=== accuracy tests ===")
    assert (
        "Induction"
        in os.popen(
            "./sing sha256 fc01e30ec13d561fbb19c383a98c27128a0d4ccce9708e9cd52c137fd9cdf6c7 < test.txt"
        ).read()
    ), "sing sha256 should find correct password"
    assert (
        os.popen(
            "./sing sha256 fc01e30ec13d561fbb19c383a98c27128a0d4ccce9708e9cd52c137fd9cdf6c7 < wow.txt"
        )
        .read()
        .strip()
        == ""
    ), "sing sha256 should not find correct password"
    assert (
        "Induction"
        in os.popen(
            "./sing wpa 436f686572657200 000d9382363a 000c4182b255 cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386 3e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933 0203007502010a00100000000000000000cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d3860000000000000000000000000000000000000000000000000000000000000000a462a7029ad5ba30b6af0df391988e45001630140100000fac020100000fac040100000fac020000 a462a7029ad5ba30b6af0df391988e45 < test.txt"
        ).read()
    ), "sing wpa should find correct password"
    assert (
        os.popen(
            "./sing sha256 fc01e30ec13d561fbb19c383a98c27128a0d4ccce9708e9cd52c137fd9cdf6c7 < wow.txt"
        )
        .read()
        .strip()
        == ""
    ), "sing wpa should not find correct password"
    print("eyalthesinger: passed")

    print("=== sha256 ===")
    measure_command(
        "../../john/run/john -w=rockyou.txt -form=raw-sha256 induction-sha.txt",
        "johntheripper",
    )
    measure_command(
        "./sing sha256 fc01e30ec13d561fbb19c383a98c27128a0d4ccce9708e9cd52c137fd9cdf6c7",
        "eyalthesinger",
        "rockyou.txt",
    )
    print("=== wpa2 ===")
    measure_command(
        "../../john/run/john -w=testing.txt -form=wpapsk induction.john",
        "johntheripper",
    )
    measure_command(
        "./sing wpa 436f686572657200 000d9382363a 000c4182b255 cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386 3e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933 0203007502010a00100000000000000000cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d3860000000000000000000000000000000000000000000000000000000000000000a462a7029ad5ba30b6af0df391988e45001630140100000fac020100000fac040100000fac020000 a462a7029ad5ba30b6af0df391988e45",
        "eyalthesinger",
        "testing.txt",
    )
