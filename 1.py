"""
Email Header Analyzer – Tracking Emails & Investigating Email Crimes
Objective: Extract fields, IPs, and detect suspicious signs in email headers
"""

import re
import json
from email.parser import HeaderParser
from email.utils import parsedate_to_datetime

# ------------------ Helper Functions ------------------

def extract_ips(text):
    """Extract IPv4 and IPv6 addresses using regex."""
    pattern = r'(?:\d{1,3}\.){3}\d{1,3}|\[?[A-F0-9:]+\]?'
    return re.findall(pattern, text, flags=re.IGNORECASE)

def parse_header(raw_header):
    """Parse header and return email fields and received headers."""
    header = raw_header.replace('\r\n', '\n').replace('\r', '\n')
    header = re.sub(r'\n[ \t]+', ' ', header)  # unfold folded lines
    parser = HeaderParser()
    msg = parser.parsestr(header)
    
    fields = {k: msg.get(k) for k in [
        "From","To","Date","Subject","Message-ID","Return-Path",
        "Reply-To","Authentication-Results","DKIM-Signature",
        "Received-SPF","X-Originating-IP"]}
    
    received_headers = msg.get_all("Received", [])
    return fields, received_headers

def analyze_ips(received_headers, x_orig_ip):
    """Aggregate all IPs from Received headers and X-Originating-IP."""
    all_ips, received_info = set(), []
    for rec in received_headers:
        ips = extract_ips(rec)
        all_ips.update(ips)
        received_info.append({"raw": rec, "ips": ips})
    if x_orig_ip:
        all_ips.update(extract_ips(x_orig_ip))
    return list(all_ips), received_info

def check_suspicion(fields, received_headers, all_ips):
    """Run basic checks to generate suspicion flags."""
    flags = []

    auth_result = (fields.get("Authentication-Results") or "") + (fields.get("Received-SPF") or "")
    if auth_result.strip() and "pass" not in auth_result.lower():
        flags.append(" Authentication failed or suspicious SPF/DKIM result")

    # Domain mismatch checks
    from_field, msg_id, rp = fields.get("From") or "", fields.get("Message-ID") or "", fields.get("Return-Path")
    if "@" in from_field and "@" in msg_id:
        if from_field.split("@")[-1].split(">")[0].strip() != msg_id.split("@")[-1].split(">")[0].strip():
            flags.append(" Domain mismatch between From and Message-ID")
    if rp:
        if rp.split("@")[-1].replace(">", "").strip() != from_field.split("@")[-1].replace(">", "").strip():
            flags.append(" Return-Path and From domains differ")

    # Timestamp order check
    try:
        times = [parsedate_to_datetime(re.search(r";\s*(.+)", r).group(1)) for r in received_headers if re.search(r";\s*(.+)", r)]
        if any(times[i] < times[i+1] for i in range(len(times)-1)):
            flags.append(" Non-monotonic timestamps detected (possible tampering)")
    except Exception:
        pass

    if not received_headers:
        flags.append(" No Received headers found (cannot trace route)")
    if not all_ips:
        flags.append(" No IP addresses found in headers")

    return flags

def summarize(fields, received_info, all_ips, flags):
    """Print summary and save JSON report."""
    summary = {
        "From": fields["From"], "To": fields["To"], "Subject": fields["Subject"],
        "Message-ID": fields["Message-ID"], "Total Received Hops": len(received_info),
        "Observed IPs": all_ips[:5], "Suspicion Flags": flags
    }
    print("\n--- EMAIL HEADER SUMMARY ---")
    for k,v in summary.items():
        print(f"{k}: {v}")

    print("\n--- DETAILED RECEIVED HEADERS ---")
    for i, r in enumerate(received_info, 1):
        print(f"{i}. {r['raw']}")
        if r['ips']: print("   IPs:", ", ".join(r['ips']))

    print("\n--- SUSPICION FLAGS ---")
    if flags: [print(f) for f in flags]
    else: print(" No suspicious activity detected.")

    # Save JSON
    json_report = {"Fields": fields, "Received": received_info, "IPs": all_ips, "Flags": flags}
    with open("email_report.json", "w") as f: json.dump(json_report, f, indent=4)
    print("\nJSON report saved as 'email_report.json'.")

# ------------------ Main ------------------

if __name__ == "__main__":
    print(" Email Header Analyzer")
    choice = input("Enter file path or press Enter to paste header manually: ").strip()

    if choice:
        try: raw_header = open(choice).read()
        except FileNotFoundError: print(" File not found!"); exit()
    else:
        print("Paste the email header below (end with a blank line):")
        lines = iter(input, "")
        raw_header = "\n".join(lines)

    if not raw_header.strip(): print(" No input provided!")
    else:
        fields, received_headers = parse_header(raw_header)
        all_ips, received_info = analyze_ips(received_headers, fields.get("X-Originating-IP"))
        flags = check_suspicion(fields, received_headers, all_ips)
        summarize(fields, received_info, all_ips, flags)
