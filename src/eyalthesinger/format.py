import click
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon
from scapy.layers.eap import EAPOL, EAPOL_KEY
from scapy.utils import rdpcap


@click.command()
@click.argument("cipher")
@click.argument("filename")
def format(cipher: str, filename: str):
    """ processes a pcap file and extracts the necessary information for wpa2 cracking:
        server and client macs, server and client nonces, client key mic, raw bytes of the eapol layer of the second handshake packet and ssid"""
    
    if cipher == "wpa":
        assert filename.endswith("cap")
        capture = rdpcap(filename)

        for handshake_index, p in enumerate(capture[EAPOL_KEY]):
            if handshake_index == 0:
                # the server nonce and both client and server mac's can be found in the first handshake packet
                server_nonce = p[EAPOL_KEY].key_nonce
                server_mac = p[Dot11].addr3
                client_mac = p[Dot11].addr1
            elif handshake_index == 1:
                # the client nonce and client key mic can be found in the second handshake packet.
                # we also need the entire eapol layer for cracking
                client_nonce = p[EAPOL_KEY].key_nonce
                client_key_mic = p[EAPOL_KEY].key_mic
                second_packet = bytes(p[EAPOL])

        for p in capture[Dot11Beacon]:
            # the beacon packet contains the SSID
            if p[Dot11].addr2 == server_mac and p[Dot11Elt].ID == 0:
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
