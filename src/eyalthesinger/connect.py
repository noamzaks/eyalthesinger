"""
Networking client:
Connects to the server in order to get jobs
"""

import click
import socket
import multiprocessing
import sys
import io

from crack import crack
from utilities import socket_recieve_full_message, socket_send_full_message


def monitor_crack_output(output_buffer: io.StringIO):
    """
    Recieves a buffer from crack_wordlist, containing "crack"'s output.
    Searches for either a success (and the password recieved) or failure.
    """

    contents = output_buffer.getvalue()
    if "Found password " in contents:
        start_index = contents.index("Found password ") + len("Found password ")
        end_index = contents.find('.', start_index)
        password = contents[start_index: end_index]
        return password
    if "Couldn't crack" in contents:
        return None


def crack_wordlist(server_instruction: dict):
    """
    parses cipher type, target hash and wordlist recieved from server, calls our crack function
    """
    try:
        target_hash = server_instruction["target_hash"]
        wordlist = server_instruction["wordlist"]
        cipher = server_instruction["cipher"]
    except Exception:
        raise Exception(
                "error in crack_wordlist: missing argument"
            )
    
    print("started working on cracking job!")

    buffer = io.StringIO()
    sys.stdout = buffer
    crack(cipher, wordlist, target_hash, jobs=multiprocessing.cpu_count())
    result = monitor_crack_output(buffer)
    sys.stdout = sys.__stdout__
    buffer.close()

    print("finished working on cracking job!")

    return result


def report_cpu_info(server_instruction: dict):
    """
    returns cpu count.
    """
    return multiprocessing.cpu_count()


def handle_server_instruction(server_instruction: dict, client: socket.socket):
    """
    recieves a full server instruction as bytes, parses and calls the appropriate instruction handler.
    prepares a response and returns it.
    """

    instruction_handlers = {"crack_wordlist": crack_wordlist, "report_cpu_info": report_cpu_info}
    try:
        if "instructionType" in server_instruction:
            instruction_ret = instruction_handlers[server_instruction["instructionType"]](server_instruction)
            response = {"instructionType": server_instruction["instructionType"], "data": instruction_ret}
        else:
            raise Exception(
                "server instruction missing"
            )
    except Exception:
         raise Exception(
                "invalid server instruction"
            )
    
    socket_send_full_message(client, response)



def handle_connection(client: socket.socket):
    """
    Waits for instructions from the server, each time handling an instruction in a new subprocess.
    """
    instruction_subprocesses = []

    while True:
        curr_instruction = socket_recieve_full_message(client)
        if not curr_instruction:
            break
        curr_subprocess = multiprocessing.Process(target=handle_server_instruction, args=(curr_instruction, client))
        instruction_subprocesses.append(curr_subprocess)
        curr_subprocess.start()

    for subprocess in instruction_subprocesses:
        subprocess.join()

    print("server closed connection and all subprocesses have finished!")


# @click.command()
@click.argument("ip")
@click.argument("port", required=False)
def connect(ip: str, port: int = 1574):
    # try to connect to server
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ip, port))
    except Exception:
        raise Exception(
                f"cannot connect to server ({ip}, {port})"
            )
    
    # handle the connection
    handle_connection(client)