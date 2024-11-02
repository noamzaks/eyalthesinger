from scapy.all import rdpcap, wrpcap
from scapy.layers.eap import EAPOL, EAPOL_KEY
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11AssoReq, Dot11ProbeResp
import os

from generate_pcap import mic, NONCE_LENGTH

MAC_BROADCAST = 'ff:ff:ff:ff:ff:ff'

packets = rdpcap('data/capture2.pcap')

mac_translation_tables = {}

def translate_mac(address: str):
    global mac_translation_tables
    if address == MAC_BROADCAST:
        return MAC_BROADCAST
    if address not in mac_translation_tables:
        mac_translation_tables[address] = os.urandom(6).hex(':')
    return mac_translation_tables[address]

server_nonce = os.urandom(NONCE_LENGTH)
client_nonce = os.urandom(NONCE_LENGTH)

# Fix mac addresses
packets[3].addr2 = packets[5].addr2

for p in packets[Dot11]:
    p.addr1 = translate_mac(p.addr1)
    p.addr2 = translate_mac(p.addr2)
    p.addr3 = translate_mac(p.addr3)

# Fix nonces

packets[EAPOL_KEY][0].key_nonce = server_nonce
packets[EAPOL_KEY][1].key_nonce = client_nonce
packets[EAPOL_KEY][2].key_nonce = server_nonce

# Fix SSIDs

SSID = 'Network1'

packets[0][Dot11ProbeResp].info = 'Network4'
packets[0][Dot11ProbeResp].len = len(packets[0][Dot11ProbeResp].info)

packets[1][Dot11ProbeResp].info = 'Network3'
packets[1][Dot11ProbeResp].len = len(packets[1][Dot11ProbeResp].info)

packets[2][Dot11ProbeResp].info = 'Network2'
packets[2][Dot11ProbeResp].len = len(packets[2][Dot11ProbeResp].info)

packets[3][Dot11Beacon].info = SSID
packets[3][Dot11Beacon].len = len(packets[3][Dot11Beacon].info)

packets[6][Dot11AssoReq].info = SSID
packets[6][Dot11AssoReq].len = len(packets[6][Dot11AssoReq].info)

PASSPHRASE = 'lets calculate'

# Fix mic
for p in packets[EAPOL_KEY][1:]:
    p.key_mic = mic(PASSPHRASE, SSID, bytes.fromhex(p.addr1.replace(':', '')), bytes.fromhex(p.addr2.replace(':', '')), client_nonce, server_nonce, bytes(p[EAPOL]))


wrpcap('out.pcap', packets)