# ttn_auditor_app.py
#
# A single-file, modular Streamlit dashboard for connecting to The Things Network (TTN)
# and performing live analysis on LoRaWAN packets with a simple auditing framework.

import streamlit as st
import ttn
import pandas as pd
from queue import Queue
import threading
from datetime import datetime

# ==============================================================================
# 1. TTN Client Module
#
# Encapsulates the logic for connecting to the TTN MQTT broker.
# It runs in a separate thread to avoid blocking the Streamlit app.
# ==============================================================================
# ==============================================================================
# 1. NEW TTN Client Module (for V3)
#
# Replaces the old TTNClient class. Uses the paho-mqtt library.
# ==============================================================================
import paho.mqtt.client as mqtt
import json

class TTNClient:
    """A V3 client using paho-mqtt to connect to The Things Stack."""

    def __init__(self, app_id: str, access_key: str, ttn_cluster: str):
        self.app_id = app_id
        self.access_key = access_key
        # Construct the V3 server address, username, and topics
        self.mqtt_server = f"{ttn_cluster}.cloud.thethings.network"
        self.mqtt_port = 8883
        self.mqtt_user = f"{app_id}@ttn"
        self.uplink_topic = f"v3/{self.mqtt_user}/devices/+/up"

        self.data_queue = Queue()
        self.client = mqtt.Client()
        self.client.username_pw_set(self.mqtt_user, self.access_key)
        self.client.tls_set() # Use TLS for a secure connection
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print("Successfully connected to TTN V3 MQTT.")
            # Subscribe to all uplink events for all devices
            client.subscribe(self.uplink_topic)
            print(f"Subscribed to uplink topic: {self.uplink_topic}")
        else:
            print(f"Failed to connect, return code {rc}\n")

    def _on_message(self, client, userdata, msg):
        """Callback for when a message is received."""
        print(f"Uplink received on topic: {msg.topic}")
        try:
            # The payload is JSON, decode it
            json_payload = json.loads(msg.payload.decode('utf-8'))
            self.data_queue.put(json_payload)
        except Exception as e:
            print(f"Error processing message: {e}")

    def connect(self):
        """Connects and starts the client loop in a separate thread."""
        try:
            self.client.connect(self.mqtt_server, self.mqtt_port, 60)
            # loop_start() runs the network loop in a background thread
            self.client.loop_start()
        except Exception as e:
            print(f"Error connecting to TTN: {e}")
            raise

    def disconnect(self):
        """Stops the loop and disconnects the client."""
        self.client.loop_stop()
        self.client.disconnect()
        print("Disconnected from TTN.")


# ==============================================================================
# 2. UPDATED LoRaWAN Auditing Framework (LAF) Module
#
# This version is updated to parse the TTN V3 JSON data structure.
# ==============================================================================
class LoRaWANAuditor:
    """Performs security and performance audits on LoRaWAN packets from TTN V3."""

    FRAME_COUNTER_GAP_THRESHOLD = 10
    WEAK_SIGNAL_RSSI_THRESHOLD = -110

    def __init__(self):
        if 'device_state' not in st.session_state:
            st.session_state.device_state = {}

    def _get_device_state(self, dev_id):
        if dev_id not in st.session_state.device_state:
            st.session_state.device_state[dev_id] = {'last_fcnt': None}
        return st.session_state.device_state[dev_id]

    def audit_packet(self, msg: dict) -> list:
        """
        Runs all available audit checks on a single packet message (V3 JSON format).
        Returns a list of findings.
        """
        findings = []
        # Extract the necessary nested information from the V3 JSON
        uplink_message = msg.get('uplink_message', {})
        dev_id = msg.get('end_device_ids', {}).get('device_id')

        if not dev_id or not uplink_message:
            return findings  # Not a valid uplink message

        device_state = self._get_device_state(dev_id)

        findings.extend(self._check_frame_counter(uplink_message, device_state))
        findings.extend(self._check_signal_strength(uplink_message))
        findings.extend(self._check_payload(uplink_message))

        device_state['last_fcnt'] = uplink_message.get('f_cnt')
        return findings

    def _check_frame_counter(self, uplink, state) -> list:
        last_fcnt = state.get('last_fcnt')
        current_fcnt = uplink.get('f_cnt')

        if last_fcnt is not None and current_fcnt is not None:
            gap = current_fcnt - last_fcnt
            if gap > self.FRAME_COUNTER_GAP_THRESHOLD:
                return [{'check': 'Frame Counter Gap', 'severity': 'High',
                         'details': f"Large gap detected. Last: {last_fcnt}, Current: {current_fcnt} (Gap: {gap})."}]
            elif gap <= 0:
                return [{'check': 'Frame Counter Reset/Replay', 'severity': 'Critical',
                         'details': f"Frame counter did not increment. Last: {last_fcnt}, Current: {current_fcnt}."}]
        return []

    def _check_signal_strength(self, uplink) -> list:
        best_rssi = -200
        gateways = uplink.get('rx_metadata', [])
        if gateways:
            for gateway in gateways:
                if gateway.get('rssi', -200) > best_rssi:
                    best_rssi = gateway['rssi']

            if best_rssi < self.WEAK_SIGNAL_RSSI_THRESHOLD:
                return [{'check': 'Weak Signal', 'severity': 'Medium',
                         'details': f"Packet received with very weak signal (Best RSSI: {best_rssi} dBm)."}]
        return []

    def _check_payload(self, uplink) -> list:
        if not uplink.get('decoded_payload'):
            return [{'check': 'Empty Decoded Payload', 'severity': 'Low',
                     'details': "No decoded payload found. Ensure a payload formatter is active."}]
        return []


# ==============================================================================
# 3. Streamlit Application UI Module
#
# This is the complete and corrected class for the user interface.
# ==============================================================================
class StreamlitApp:
    """The main Streamlit application logic."""

    def __init__(self):
        st.set_page_config(page_title="LoRaWAN Audit Framework", layout="wide")
        self.auditor = LoRaWANAuditor()
        # Initialize session state variables
        if 'ttn_client' not in st.session_state:
            st.session_state.ttn_client = None
        if 'packets' not in st.session_state:
            st.session_state.packets = []
        if 'is_connected' not in st.session_state:
            st.session_state.is_connected = False

    def _display_packet(self, packet_data: dict, findings: list):
        """Renders a single V3 packet and its audit findings in an expander."""
        timestamp = packet_data.get('received_at', datetime.now().isoformat())
        dev_id = packet_data.get('end_device_ids', {}).get('device_id', 'Unknown Device')
        uplink = packet_data.get('uplink_message', {})
        f_cnt = uplink.get('f_cnt', 'N/A')

        with st.expander(
                f"**{timestamp.split('T')[1].split('.')[0]}Z** | **Device ID:** `{dev_id}` | **FCnt:** `{f_cnt}` | **Findings:** `{len(findings)}`"):
            st.subheader("Audit Findings")
            if findings:
                df_findings = pd.DataFrame(findings)
                st.table(df_findings.style.apply(self._color_severity, axis=1))
            else:
                st.success("✅ No issues detected.")

            st.subheader("Packet Details")
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Core Info**")
                st.json({
                    "Device ID": dev_id,
                    "Frame Counter": f_cnt,
                    "Port": uplink.get('f_port'),
                    "Correlation IDs": packet_data.get('correlation_ids')
                })
            with col2:
                st.write("**Decoded Payload**")
                st.json(uplink.get('decoded_payload') or {"status": "No decoded fields"})

            st.write("**Gateway Metadata**")
            gateways_info = [{
                "ID": gw.get('gateway_ids', {}).get('gateway_id'), "RSSI": gw.get('rssi'), "SNR": gw.get('snr'),
                "Timestamp": gw.get('time')
            } for gw in uplink.get('rx_metadata', [])]
            if gateways_info:
                st.dataframe(gateways_info)
            else:
                st.info("No gateway metadata available.")

    def _color_severity(self, row):
        """Applies color to the findings table based on severity."""
        color = ''
        severity = row['severity']
        if severity == 'Critical':
            color = 'background-color: #ff4b4b; color: white'
        elif severity == 'High':
            color = 'background-color: #ff8c8c'
        elif severity == 'Medium':
            color = 'background-color: #ffdb58'
        return [color] * len(row)

    def _process_queue(self):
        """Processes all messages currently in the data queue."""
        if st.session_state.ttn_client:
            q = st.session_state.ttn_client.data_queue
            while not q.empty():
                msg = q.get()
                findings = self.auditor.audit_packet(msg)
                # Add to the beginning of the list to show newest first
                st.session_state.packets.insert(0, (msg, findings))
                # Limit stored packets to prevent memory issues
                st.session_state.packets = st.session_state.packets[:100]

    def run(self):
        """Main execution method for the Streamlit app."""
        st.title("🛰️ Live LoRaWAN Auditing Framework (LAF)")
        st.markdown("Connect to your TTN application to monitor and audit live device data.")

        # --- Sidebar for Connection Management ---
        with st.sidebar:
            st.header("TTN V3 Credentials")
            app_id = st.text_input("Application ID", value=st.session_state.get('app_id', ''))
            access_key = st.text_input("Access Key", type="password", value=st.session_state.get('access_key', ''))
            ttn_cluster = st.text_input("TTN Cluster", help="e.g., eu1, nam1, au1",
                                        value=st.session_state.get('ttn_cluster', 'eu1'))

            if st.session_state.is_connected:
                if st.button("🔌 Disconnect"):
                    st.session_state.ttn_client.disconnect()
                    st.session_state.is_connected = False
                    st.session_state.ttn_client = None
                    st.success("Disconnected.")
                    st.rerun()
            else:
                if st.button("🚀 Connect to TTN"):
                    if not app_id or not access_key or not ttn_cluster:
                        st.error("Please provide Application ID, Access Key, and Cluster.")
                    else:
                        st.session_state.app_id = app_id
                        st.session_state.access_key = access_key
                        st.session_state.ttn_cluster = ttn_cluster
                        try:
                            with st.spinner("Connecting to TTN V3..."):
                                client = TTNClient(app_id, access_key, ttn_cluster)
                                client.connect()
                                st.session_state.ttn_client = client
                                st.session_state.is_connected = True
                            st.success("Connection successful! Waiting for data...")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to connect: {e}")

        # --- Main Dashboard Area ---
        if not st.session_state.is_connected:
            st.info("Please connect to a TTN application using the sidebar.")
        else:
            st.header("🔴 Live Packet Feed")
            self._process_queue()

            if not st.session_state.packets:
                st.info("Waiting for the first uplink message from a device...")
            else:
                for packet, findings in st.session_state.packets:
                    self._display_packet(packet, findings)

        # Trigger a periodic rerun to check the queue
        if st.session_state.is_connected:
            import time
            time.sleep(2)
            st.rerun()
# ==============================================================================
# 4. Script Entrypoint
# ==============================================================================
if __name__ == "__main__":
    app = StreamlitApp()
    app.run()