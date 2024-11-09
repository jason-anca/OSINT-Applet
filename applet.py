import tkinter as tk
import webbrowser
import re

# Function to generate URLs for IP or hash lookups
def generate_osint_links(input_value):
    # Determine if the input is an IP address or a file hash
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", input_value):  # Basic IP address regex
        # Generate URLs for IP lookups
        return {
            "VirusTotal (IP)": f"https://www.virustotal.com/gui/ip-address/{input_value}/detection",
            "AbuseIPDB": f"https://www.abuseipdb.com/check/{input_value}",
            "Spur": f"https://spur.us/context/{input_value}"
        }
    elif re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", input_value):
        # Generate URLs for hash lookups
        return {
            "VirusTotal (Hash)": f"https://www.virustotal.com/gui/file/{input_value}/detection",
            "IBM X-Force": f"https://exchange.xforce.ibmcloud.com/malware/{input_value}",
            "OTX AlienVault": f"https://otx.alienvault.com/indicator/file/{input_value}"
        }
    else:
        return None

# Function to perform OSINT lookup and open links in the browser
def perform_osint():
    input_value = input_entry.get().strip()
    if input_value:
        # Generate and open OSINT links based on the input type
        links = generate_osint_links(input_value)
        if links:
            for site, url in links.items():
                webbrowser.open(url)
            result_label.config(text=f"Performed lookup on: {input_value}")
        else:
            result_label.config(text="Invalid input. Please enter a valid IP address or hash.")
    else:
        result_label.config(text="Please enter a value.")

root = tk.Tk()
root.title("OSINT Lookup Tool")
root.geometry("400x250")

# Create and place widgets
input_label = tk.Label(root, text="Enter IP address or file hash:")
input_label.pack(pady=10)

input_entry = tk.Entry(root, width=40)
input_entry.pack(pady=5)

lookup_button = tk.Button(root, text="Perform Lookup", command=perform_osint)
lookup_button.pack(pady=10)

result_label = tk.Label(root, text="")
result_label.pack(pady=10)

# Run the Tkinter event loop
root.mainloop()