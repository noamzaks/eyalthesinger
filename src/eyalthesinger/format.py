import click
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon
from scapy.layers.eap import EAPOL, EAPOL_KEY
from scapy.utils import rdpcap


@click.command()
@click.argument("cipher")
@click.argument("filename")
def format(cipher: str, filename: str):
    if cipher == "wpa":
        assert filename.endswith("cap")
        capture = rdpcap(filename)

        # TODO: output multiple options, if found?
        for handshake_index, p in enumerate(capture[EAPOL_KEY]):
            if handshake_index == 0:
                server_nonce = p[EAPOL_KEY].key_nonce
                server_mac = p[Dot11].addr3
                client_mac = p[Dot11].addr1
            elif handshake_index == 1:
                client_nonce = p[EAPOL_KEY].key_nonce
                client_key_mic = p[EAPOL_KEY].key_mic
                second_packet = bytes(p[EAPOL])

        # for p in capture[Dot11ProbeResp]:
        #     if p[Dot11].addr2 == server_mac and p[Dot11Elt].ID == 0:  # SSID
        #         ssid = p[Dot11Elt].info
        #         break
        for p in capture[Dot11Beacon]:
            if p[Dot11].addr2 == server_mac and p[Dot11Elt].ID == 0:  # SSID
                ssid = p[Dot11Beacon].info
                break

        hash = ":".join(
            [
                (ssid + b"\x00").hex(),
                client_mac.replace(":", ""),
                server_mac.replace(":", ""),
                client_nonce.hex(),
                server_nonce.hex(),
                second_packet.hex(),
                client_key_mic.hex(),
            ]
        )
        print(hash)
