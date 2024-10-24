import urllib.request
import socket
import json
from typing import Optional
from tqdm import tqdm

MESSAGE_SIZE = 1024
DATA_SIZE = MESSAGE_SIZE - 1
STOP_BYTE = b"\x00"
DONT_STOP_BYTE = b"\x01"


# Source: https://stackoverflow.com/questions/15644964/python-progress-bar-and-downloads
class DownloadProgressBar(tqdm):
    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)


def download_url(url: str, output_path: Optional[str] = None):
    if output_path is None:
        output_path = url.split("/")[-1]

    with DownloadProgressBar(
        unit="B", unit_scale=True, miniters=1, desc=url.split("/")[-1]
    ) as t:
        urllib.request.urlretrieve(url, filename=output_path, reporthook=t.update_to)


def socket_recieve_full_message(s: socket.socket):
    """
    Receives a full message from the socket.
    If a message's last bytes is 0, indicates end of message, otherwise keeps reading.
    All messages will be padded to MESSAGE_SIZE
    """
    current_message = b""
    while True:
        partial_message = s.recv(MESSAGE_SIZE)
        if not partial_message:
            return None
        current_message += partial_message[:-1]
        if partial_message[-1:] == STOP_BYTE:
            break
    
    return json.loads(current_message.decode('utf-8'))


def socket_send_full_message(s: socket.socket, message: dict):
    """
    Sends a full message on the socket.
    Pads accordingly.
    """

    message_bytes = json.dumps(message).encode('utf-8')

    for i in range(0, len(message_bytes), DATA_SIZE):
        if i + DATA_SIZE > len(message_bytes):
            s.send(message_bytes[i:] + STOP_BYTE)
        else:
            s.send(message_bytes[i: i + DATA_SIZE] + DONT_STOP_BYTE)
