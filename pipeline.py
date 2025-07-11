import json
import argparse
import struct
import pandas as pd
from binascii import unhexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

# Constants
UP_LINK = 0
DOWN_LINK = 1


# LoRaMAC decryption function
def loramac_decrypt(payload_hex, sequence_counter, key, dev_addr, direction=UP_LINK):
    key = unhexlify(key)
    dev_addr = unhexlify(dev_addr)
    buffer = bytearray(unhexlify(payload_hex))
    size = len(buffer)
    bufferIndex = 0
    ctr = 1
    encBuffer = [0x00] * size

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    def aes_encrypt_block(aBlock):
        encryptor = cipher.encryptor()
        return bytearray(encryptor.update(bytes(aBlock)) + encryptor.finalize())

    aBlock = bytearray([
        0x01, 0x00, 0x00, 0x00, 0x00, direction,
        dev_addr[3], dev_addr[2], dev_addr[1], dev_addr[0],
        sequence_counter & 0xFF, (sequence_counter >> 8) & 0xFF,
        (sequence_counter >> 16) & 0xFF, (sequence_counter >> 24) & 0xFF,
        0x00, 0x00
    ])

    while size >= 16:
        aBlock[15] = ctr & 0xFF
        ctr += 1
        sBlock = aes_encrypt_block(aBlock)
        for i in range(16):
            encBuffer[bufferIndex + i] = buffer[bufferIndex + i] ^ sBlock[i]
        size -= 16
        bufferIndex += 16

    if size > 0:
        aBlock[15] = ctr & 0xFF
        sBlock = aes_encrypt_block(aBlock)
        for i in range(size):
            encBuffer[bufferIndex + i] = buffer[bufferIndex + i] ^ sBlock[i]

    return encBuffer


# LorawanCrypto class for MIC verification and payload decryption
class LorawanCrypto:
    def __init__(self, nwkskey, appskey):
        self.nwkskey = unhexlify(nwkskey)
        self.appskey = unhexlify(appskey)

    def verify_mic(self, msg, fcnt, devaddr, mic_received):
        # Calculate MIC using AES-CMAC as per LoRaWAN spec
        b0 = bytearray([
            0x49, 0x00, 0x00, 0x00, 0x00, UP_LINK,
            *unhexlify(devaddr)[::-1],
            fcnt & 0xFF, (fcnt >> 8) & 0xFF, 0x00, 0x00,
            0x00, len(msg)
        ])
        data = b0 + msg
        c = cmac.CMAC(algorithms.AES(self.nwkskey), backend=default_backend())
        c.update(data)
        computed_mic = c.finalize()[:4]
        return computed_mic == mic_received

    def decrypt_frm_payload(self, frm_payload, fcnt, devaddr, direction, fport):
        key = self.nwkskey if fport == 0 else self.appskey
        devaddr_bytes = unhexlify(devaddr)
        decrypted = loramac_decrypt(frm_payload.hex(), fcnt, key.hex(), devaddr, direction)
        return bytes(decrypted)


# Parse and decrypt a single LoRaWAN packet
def parse_and_decrypt(raw_payload_hex, nwkskey, appskey):
    try:
        phy_payload = bytes.fromhex(raw_payload_hex)
        mhdr = phy_payload[0:1]  # Extract components from PHYPayload
        mac_payload = phy_payload[1:-4]
        mic_received = phy_payload[-4:]

        devaddr = mac_payload[0:4][::-1]  # Reverse for big-endian
        fctrl = mac_payload[4:5]
        fcnt = int.from_bytes(mac_payload[5:7], 'little')
        fopts_len = fctrl[0] & 0x0F
        fopts = mac_payload[7:7 + fopts_len]

        payload_offset = 7 + fopts_len
        if len(mac_payload) <= payload_offset:
            return {"error": "Missing FPort/FRMPayload"}

        fport = mac_payload[payload_offset:payload_offset + 1]
        frm_payload = mac_payload[payload_offset + 1:]
        fport_val = int.from_bytes(fport, 'big')

        devaddr_hex = devaddr.hex().upper()
        crypto = LorawanCrypto(nwkskey, appskey)

        mic_is_valid = crypto.verify_mic(mhdr + mac_payload, fcnt, devaddr_hex, mic_received)
        if not mic_is_valid:
            return {"error": "MIC validation failed"}

        decrypted_payload = crypto.decrypt_frm_payload(frm_payload, fcnt, devaddr_hex, UP_LINK, fport_val)

        # Decode application data (assuming float temp + int humidity)
        try:
            temp, humidity = struct.unpack("<fB", decrypted_payload)
            app_data = {"temperature": round(temp, 2), "humidity": humidity}
        except struct:

            return {
            "devaddr": devaddr_hex,
            "fcnt": fcnt,
            "fport": fport_val,
            "mic_ok": mic_is_valid,
            "decrypted_payload_hex": decrypted_payload.hex(),
            "temperature": round(temp, 2),
            "humidity": humidity,
            "error": None
        }
    except Exception as e:
        return {"error": str(e)}


# Main pipeline function with additional analyses
def main():
    parser = argparse.ArgumentParser(description="LoRaWAN Packet Processing and Analysis Pipeline")
    parser.add_argument("--input", required=True, help="Input JSON dataset file (e.g., packets.json)")
    parser.add_argument("--nwkskey", required=True, help="Network Session Key (hex-encoded)")
    parser.add_argument("--appskey", required=True, help="Application Session Key (hex-encoded)")
    parser.add_argument("--out", default="out", help="Output prefix for CSV and JSON files")
    args = parser.parse_args()

    # Load dataset
    with open(args.input, 'r') as f:
        dataset = json.load(f)

    # Process packets
    results = []
    for packet in dataset:
        parsed_data = parse_and_decrypt(packet["raw_payload"], args.nwkskey, args.appskey)
        combined_result = {**packet, **parsed_data}
        results.append(combined_result)

    # Convert to DataFrame
    df = pd.DataFrame(results)

    # Export processed data
    csv_path = f"{args.out}_processed_packets.csv"
    json_path = f"{args.out}_processed_packets.json"
    df.to_csv(csv_path, index=False)
    df.to_json(json_path, orient='records', indent=2)
    print(f"✅ Exported CSV to {csv_path}")
    print(f"✅ Exported JSON to {json_path}")

    # Additional LoRa analyses
    print("\n### LoRa Packet Analysis ###")

    # Packet count per device
    packet_counts = df['devaddr'].value_counts()
    print("\n**Packet Count per Device:**")
    for devaddr, count in packet_counts.items():
        print(f"- DevAddr {devaddr}: {count} packets")

    # Signal strength analysis (if RSSI/SNR present)
    if 'rssi' in df.columns and 'snr' in df.columns:
        avg_rssi = df['rssi'].mean()
        avg_snr = df['snr'].mean()
        print("\n**Signal Strength Statistics:**")
        print(f"- Average RSSI: {avg_rssi:.2f} dBm")
        print(f"- Average SNR: {avg_snr:.2f} dB")

    # Error summary
    error_df = df[df['error'].notnull()]
    if not error_df.empty:
        print("\n**Packets with Errors:**")
        for idx, packet in error_df.iterrows():
            print(f"- Packet with DevAddr {packet['devaddr']}: {packet['error']}")

    # PCAP generation guidance
    print("\n💡 To generate a PCAP file for Wireshark:")
    print("Use 'lora-pcap' (https://github.com/ermites-io/lora-pcap). Example:")
    print(f"lora-pcap --input {args.input} --output lorawan.pcap --loratap")


if __name__ == "__main__":
    main()