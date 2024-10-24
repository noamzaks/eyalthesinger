"""
Networking server:
Accepts clients and splits jobs
"""

import click
import socket
import asyncio
import threading

from utilities import socket_recieve_full_message, socket_send_full_message
from download import download

MAX_CLIENTS = 100
PROMPT = "\n>>> "

stop = False
available_commands = "available commands:\n download, crack, exit, help"
clients_list = []
clients_lock = threading.Lock()


def ask_for_and_parse_cpu_info(client: socket.socket):
    """
    asks the client for cpu information and waits for response
    """
    try:
        cpu_info_message = {"instructionType": "report_cpu_info"}
        socket_send_full_message(client, cpu_info_message)
        return_message = socket_recieve_full_message(client)
        assert return_message["instructionType"] == "report_cpu_info"
        return return_message["data"]
    except:
        return None
    

def client_reciever(clients_list, ip: str, port: int):
    """
    Opens server connection, then loops and accepts incoming connections.
    For each connection, asks client for cpu information, then adds client and cpu info to the queue
    """
    try:
        # set up server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((ip, port))
        server.listen(MAX_CLIENTS)
        print(f"Server started listening on {ip}:{port}" + PROMPT, end="")

        # accept incoming connections
        while not stop:
            try:
                server.settimeout(1.0)
                client_sock, client_addr = server.accept()
                print(f"New connection! {client_addr}" + PROMPT, end="")
                cpu_info = ask_for_and_parse_cpu_info(client_sock)
                if not cpu_info:
                    client_sock.close()
                print(f"client has {cpu_info} cpu's" + PROMPT, end="")
                clients_list.append([client_sock, cpu_info])
            except socket.timeout:
                continue
            except:
                raise Exception(
                f"error in server socket"
            )
    except:
        raise Exception(
                f"error in server socket"
            )


async def wait_for_client_response(client_socket: socket.socket):
    """
    waits for client to respond
    """
    response = socket_recieve_full_message(client_socket)
    if not response:
        print("client disconnected!" + PROMPT, end="")
        clients_list = [client for client in clients_list if client[0] != client_socket]
    assert response["instructionType"] == "crack_wordlist"
    return response["data"]


async def wait_for_responses_until_success(clients_list):
    """
    waits for the clients to respond, stops upon success.
    Returns password when found, None if all clients failed
    """
    responses = [wait_for_client_response(client[0]) for client in clients_list]
    for future in asyncio.as_completed(responses):
        success = await future 
        if not success:
            continue
        else:
            return success
    return None
        


def split_and_crack(cipher: str, wordlist: str, hash: str, clients_list):
    """
    splits the wordlist between clients, according to their capabilities
    """
    
    with open(wordlist, "rb") as f:
        lines = f.read().split(b"\n")
    
    if len(clients_list) == 0:
        print("No clients available yet! Try again after clients connected" + PROMPT, end="")

    sum_jobs = sum([item[1] for item in clients_list])
    print(f"sum jobs: {sum_jobs}")
    current_index = 0

    for index, client_info in enumerate(clients_list):
        print(client_info)
        wordlist_name = f"wordlist_for_client{index}.txt"
        client_line_conuts = (len(lines) // sum_jobs) * client_info[1]  + 1
        with open(wordlist_name, "wb") as f:
            f.write(
                b"\n".join(
                    lines[
                        current_index : min(current_index + client_line_conuts, len(lines))
                    ]
                )
                + b"\n"
            )
        current_index += client_line_conuts
        client_message = {
            "instructionType": "crack_wordlist",
            "cipher": cipher,
            "target_hash": hash,
            "wordlist": wordlist_name
        }
        socket_send_full_message(client_info[0], client_message)

    print("finished splitting jobs between clients! waiting for responses" + PROMPT, end="")
    success = asyncio.run(wait_for_responses_until_success(clients_list))
    if not success:
        print("all clients failed!" + PROMPT, end = "")
    else:
        print(f"SUCCESS! password is {success}" + PROMPT, end="")

    
def user_repl(clients_list):
    """
    repl loop, waits for user instructions and handles them
    """
    while True:
        try:
            result = None
            user_input: str = input().strip()
            s = user_input.split(" ")

            if s[0] == "download":
                result = download((s[1:]))
            elif s[0] == "crack":
                if len(s) != 4:
                    print(
                        "Usage: crack [cipher] [wordlist] [target_hash]" + PROMPT, end=""
                    )
                    continue
                result = split_and_crack(s[1], s[2], s[3], clients_list)
            elif user_input == "exit":
                break
            elif user_input == "help":
                print(available_commands + PROMPT, end="")
            else:
                print(
                    "Invalid command!\n" + available_commands + PROMPT, end=""
                )

            if result is not None:
                print(result + PROMPT, end = "")

        except KeyboardInterrupt:
            print()
            break


@click.argument("ip")
@click.argument("port", required=False)
def server(ip: str, port: int = 1574):
    """
    Splits to two subprocesses: one will handle incoming client connections, and the other will handle user requests
    """
    global stop
    clients_manager = Manager()
    clients_list = clients_manager.list()

    client_reciever_thread = threading.Thread(target=client_reciever, args=(clients_list, ip, port))
    client_reciever_thread.start()

    user_repl(clients_list)

    # if user chose to exit, no need to keep waiting for clients
    stop = True
    client_reciever_thread.join()


if __name__ == "__main__":
    server("0.0.0.0", 2222)

   