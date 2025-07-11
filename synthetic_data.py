import json
import struct
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

# Configuration
NWKSKEY = bytes.fromhex("AFBE2552625141051523588265118165")
APPSKEY = bytes.fromhex("AEBE2552625141051523588265118165")
DEVADDR = bytes.fromhex("260B1ADA")

# Constants
UPLINK = 0
DOWNLINK = 1


def encrypt_payload(payload, appskey, devaddr, fcnt, direction):
    """Encrypt LoRaWAN payload using AES-128 in CTR mode"""
    size = len(payload)
    encrypted = bytearray(size)

    block_a = bytearray(16)
    block_a[0] = 0x01
    block_a[5] = direction
    block_a[6:10] = devaddr[::-1]  # Little endian
    block_a[10:14] = fcnt.to_bytes(4, 'little')

    cipher = AES.new(appskey, AES.MODE_ECB)
    block_count = (size + 15) // 16

    for i in range(1, block_count + 1):
        block_a[15] = i
        s = cipher.encrypt(bytes(block_a))

        start = (i - 1) * 16
        end = min(start + 16, size)
        for j in range(start, end):
            encrypted[j] = payload[j] ^ s[j - start]

    return bytes(encrypted)


def calculate_mic(nwkskey, msg, devaddr, fcnt, direction):
    """Calculate Message Integrity Code"""
    b0 = bytearray(16)
    b0[0] = 0x49
    b0[5] = direction
    b0[6:10] = devaddr[::-1]
    b0[10:14] = fcnt.to_bytes(4, 'little')
    b0[15] = len(msg)

    cmac = CMAC.new(nwkskey, ciphermod=AES)
    cmac.update(bytes(b0) + msg)
    return cmac.digest()[:4]


def generate_packet(fcnt, temp, humidity):
    """Generate a complete LoRaWAN packet with sensor data"""
    # Encode sensor data
    payload_cleartext = struct.pack('<fB', temp, humidity)

    # Encrypt payload
    encrypted_payload = encrypt_payload(payload_cleartext, APPSKEY, DEVADDR, fcnt, UPLINK)

    # Construct packet
    mhdr = bytes([0x40])  # Unconfirmed Data Up
    devaddr_le = DEVADDR[::-1]
    fctrl = bytes([0x00])
    fcnt_bytes = fcnt.to_bytes(2, 'little')
    fopts = b''
    fport = bytes([10])

    mac_payload = devaddr_le + fctrl + fcnt_bytes + fopts + fport + encrypted_payload
    msg = mhdr + mac_payload

    # Add MIC
    mic = calculate_mic(NWKSKEY, msg, DEVADDR, fcnt, UPLINK)
    phy_payload = msg + mic

    return {
        "timestamp": f"2025-07-08T10:{50 + fcnt:02d}:00Z",
        "frequency": 868.1,
        "sf": 7,
        "rssi": -90 + fcnt * 2,
        "snr": 7.5 - fcnt * 0.5,
        "raw_payload": phy_payload.hex().upper(),
        "metadata": {
            "temperature": temp,
            "humidity": humidity,
            "fcnt": fcnt
        }
    }


def create_dataset(num_packets=10):
    """Create a dataset with multiple packets"""
    dataset = []
    base_temp = 21.5
    base_humidity = 65

    for fcnt in range(1, num_packets + 1):
        # Simulate small variations in temperature and humidity
        temp = base_temp + (fcnt * 0.3)
        humidity = int(max(30, base_humidity - (fcnt * 0.5)))
        dataset.append(generate_packet(fcnt, temp, humidity))

    return dataset


def main():
    dataset = create_dataset(10)
    output_file = "lorawan_dataset.json"

    with open(output_file, "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"✅ Generated '{output_file}' with {len(dataset)} packets")
    print(f"🔑 Network Session Key: {NWKSKEY.hex().upper()}")
    print(f"🔑 Application Session Key: {APPSKEY.hex().upper()}")
    print(f"📡 Device Address: {DEVADDR.hex().upper()}")


if __name__ == "__main__":
    main()