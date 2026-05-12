import requests

API_KEY = "feb3f613119d49229576bc534f9ddfab7519b934facd15dd1bbe6b785897d62f"

blocked_ips = []

def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats["malicious"]

        print(f"\nIP: {ip}")
        print(f"Malicious detections: {malicious}")

        if malicious > 0:
            print("⚠️ Suspicious IP")

            blocked_ips.append(ip)

        else:
            print("✅ Safe IP")

    else:
        print("Error:", response.status_code)
        print(response.text)


# قائمة IPs للفحص
ips_to_check = [
    "8.8.8.8",
    "1.1.1.1",
    "185.220.101.1"
]

# فحص كل IP
for ip in ips_to_check:
    check_ip_virustotal(ip)


# عرض القائمة السوداء
print("\nBlocked IPs List:")
print(blocked_ips)