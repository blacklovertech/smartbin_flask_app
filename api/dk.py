import network
import time

def connect_to_wifi(ssid, password):
    wlan = network.WLAN()
    wlan.active(True)

    # Scan for available networks
    available_networks = wlan.scan()

    # Check if the target SSID is in the list of available networks
    target_network = next((net for net in available_networks if net[0] == ssid), None)

    if target_network:
        print(f"Connecting to {ssid}")
        wlan.connect(ssid, password)

        # Wait until the connection is established
        while not wlan.isconnected():
            time.sleep(1)

        print(f"Connected to WiFi: {ssid}")
    else:
        print(f"Network '{ssid}' not found")

# List of NodeMCU SSIDs and passwords
node_list = [('B01', '12345678'), ('B02', '12345678'), ('B03', '12345678')]

# Connect to the WiFi network of each NodeMCU device
for ssid, password in node_list:
    connect_to_wifi(ssid, password)
