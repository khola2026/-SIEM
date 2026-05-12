import win32evtlog
import xml.etree.ElementTree as ET
import pandas as pd

def read_windows_logs(log_type="Microsoft-Windows-Sysmon/Operational", num_events=50):
    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    logs_list = []

    try:
        query = win32evtlog.EvtQuery(
            log_type,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        )
    except Exception:
        return pd.DataFrame()

    events = win32evtlog.EvtNext(query, num_events)

    if events:
        for event in events:
            try:
                xml_data = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_data)

                event_id_elem = root.find(".//ns:EventID", ns)
                if event_id_elem is None: continue
                
                # تحويل الـ ID إلى رقم صحيح (إنجاز مهم للـ AI)
                eid = int(event_id_elem.text)
                
                data = {}
                for d in root.findall(".//ns:Data", ns):
                    data_name = d.get("Name")
                    if data_name:
                        data[data_name] = d.text

                # --- تطوير محرك اكتشاف التهديدات (Threat Detection) ---
                if eid == 3:
                    threat_label = "Network Connection"
                elif eid == 4625:
                    threat_label = "Failed Login (Brute Force Risk)"
                elif eid == 4624:
                    threat_label = "Login Success"
                elif eid == 7040:
                    threat_label = "Service Status Changed"
                elif eid == 1:
                    threat_label = "Process Creation (New App)"
                else:
                    threat_label = "System Activity"

                logs_list.append({
                    "Event ID": eid,
                    "Time": data.get("UtcTime") or data.get("CreationTime") or "N/A",
                    # استخدام 0.0.0.0 بدلاً من N/A يجعل المنظر أكثر احترافية أمنياً
                    "Source IP": data.get("SourceIp") or "0.0.0.0",
                    "Destination IP": data.get("DestinationIp") or "0.0.0.0",
                    "Process": data.get("Image") or "System Process",
                    "Threat": threat_label
                })

            except Exception:
                continue

    return pd.DataFrame(logs_list)