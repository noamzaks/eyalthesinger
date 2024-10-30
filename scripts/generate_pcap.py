#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.eap import EAPOL, EAPOL_KEY
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
import hashlib
import hmac

import os

NONCE_LENGTH = 32

SSID = 'MyHouse'
PASSPHRASE = 'LetsCalculateTheMIC'

STA_ADDR = os.urandom(6)
BSS_ID = os.urandom(6)

def calc_dynamic_B_salt(client_mac: bytes, server_mac: bytes, client_nonce: bytes, server_nonce: bytes):
    return min(server_mac, client_mac) + max(server_mac, client_mac) + min(client_nonce, server_nonce) + max(client_nonce, server_nonce)

def calc_ptk(pmk, salt, size=64):
    r = b''

    for i in range(4):
        msg = b'Pairwise key expansion' + b'\x00' + salt + bytes([i])
        r += hmac.new(pmk, msg, hashlib.sha1).digest()

    return r[:size]

def calc_mic(kck, data):
    return hmac.new(kck, data[:81] + bytes(16) + data[81+16:], hashlib.sha1).digest()[:16]

def mic(password: bytes, ssid: bytes, client_mac: bytes, server_mac: bytes, client_nonce: bytes, server_nonce: bytes, second_packet: bytes):
    pmk = PBKDF2(password, ssid, 32, 4096, hmac_hash_module=SHA1)
    dynamic_B_salt = calc_dynamic_B_salt(client_mac, server_mac, client_nonce, server_nonce)
    ptk = calc_ptk(pmk, dynamic_B_salt)
    return calc_mic(ptk[:16], second_packet)

CLIENT_NONCE = os.urandom(NONCE_LENGTH)
SERVER_NONCE = os.urandom(NONCE_LENGTH)

packets = rdpcap('data/capture.pcap')

# Beacon packet
packets[0][Dot11Beacon][Dot11Elt].len = len(SSID)
packets[0][Dot11Beacon][Dot11Elt].info = SSID
packets[0][Dot11].addr2 = BSS_ID
packets[0][Dot11].addr3 = BSS_ID


# First packet
packets[1][Dot11].addr1 = STA_ADDR # Destiniation Addess
packets[1][Dot11].addr2 = BSS_ID
packets[1][Dot11].addr3 = BSS_ID   # Source Address
packets[1][EAPOL_KEY].key_nonce = SERVER_NONCE

# Second packet
packets[2][EAPOL_KEY].key_nonce = CLIENT_NONCE
packets[2][Dot11].addr1 = BSS_ID
packets[2][Dot11].addr2 = STA_ADDR
packets[2][Dot11].addr3 = BSS_ID
packets[2][EAPOL_KEY].key_mic = mic(PASSPHRASE, SSID, STA_ADDR, BSS_ID, CLIENT_NONCE, SERVER_NONCE, bytes(packets[2][EAPOL]))

# Third packet
packets[3][EAPOL_KEY].key_nonce = CLIENT_NONCE
packets[3][Dot11].addr1 = STA_ADDR
packets[3][Dot11].addr2 = BSS_ID
packets[3][Dot11].addr3 = BSS_ID
packets[3][EAPOL_KEY].key_mic = mic(PASSPHRASE, SSID, STA_ADDR, BSS_ID, CLIENT_NONCE, SERVER_NONCE, bytes(packets[3][EAPOL]))

# Fourth packet
packets[4][Dot11].addr1 = BSS_ID
packets[4][Dot11].addr2 = STA_ADDR
packets[4][Dot11].addr3 = BSS_ID
packets[4][EAPOL_KEY].key_mic = mic(PASSPHRASE, SSID, STA_ADDR, BSS_ID, CLIENT_NONCE, SERVER_NONCE, bytes(packets[4][EAPOL]))

wrpcap("dump.pcap", packets)