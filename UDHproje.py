import scapy.all as scapy
import pandas as pd
from sklearn.ensemble import IsolationForest
import tkinter as tk
import threading
import datetime
from tkinter import messagebox, simpledialog
import matplotlib.pyplot as plt

# GUI için Tkinter kullanma (basit bir örnek)
root = tk.Tk()
root.title("Network Traffic Monitor")

# Filtreleme seçenekleri için değişkenler
selected_src_ip = tk.StringVar()
selected_dst_ip = tk.StringVar()
selected_protocol = tk.StringVar()

# Log dosyasının yolu
log_file_path = "network_traffic_log.txt"

# Ağ trafiğini yakalamak için bir fonksiyon
def capture_traffic(packet):
    try:
        time = datetime.datetime.fromtimestamp(packet.time).strftime('%H:%M:%S')
        src = packet[scapy.IP].src if packet.haslayer(scapy.IP) else None
        dst = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else None
        sport = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) else None)
        dport = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else None)
        length = len(packet)

        # Paket türünü belirleme
        if packet.haslayer(scapy.TCP):
            pkt_type = 'TCP'
        elif packet.haslayer(scapy.UDP):
            pkt_type = 'UDP'
        elif packet.haslayer(scapy.ICMP):
            pkt_type = 'ICMP'
        else:
            pkt_type = 'Other'

        data = [time, src, dst, sport, dport, length, pkt_type]

        # Filtreleme koşulları
        if (selected_src_ip.get() == "" or src == selected_src_ip.get()) and \
           (selected_dst_ip.get() == "" or dst == selected_dst_ip.get()) and \
           (selected_protocol.get() == "" or pkt_type == selected_protocol.get()):

            # Verilerin tam olup olmadığını kontrol etme
            if all(item is not None for item in data):
                return data
            else:
                print(f"Incomplete or None data: {data}")
                return None
        return None
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

# Trafiği log dosyasına kaydetme
def log_traffic(data):
    global log_file_path
    with open(log_file_path, "a") as log_file:
        log_file.write(f"{data}\n")

# Trafiği yakalama işlemini durdurmak için bir bayrak
stop_sniffing = threading.Event()

# Yakalama fonksiyonunu arka planda çalıştırma
def start_sniffing():
    global df
    while not stop_sniffing.is_set():
        packets = scapy.sniff(iface='Wi-Fi', prn=capture_traffic, timeout=5, stop_filter=lambda x: stop_sniffing.is_set())
        packet_data = [capture_traffic(packet) for packet in packets if capture_traffic(packet) is not None]

        if packet_data:
            new_df = pd.DataFrame(packet_data, columns=columns)
            df = pd.concat([df, new_df], ignore_index=True)

            # Modeli paket uzunluğu ve port numaraları ile eğit
            model.fit(df[['Length', 'Source Port', 'Destination Port']])
            df['Anomaly'] = model.predict(df[['Length', 'Source Port', 'Destination Port']])
            log_anomalies()

# Anomalileri log dosyasına kaydetme
def log_anomalies():
    anomalies = df[df['Anomaly'] == -1]
    for index, row in anomalies.iterrows():
        anomaly_reason = detect_anomaly_reason(row)
        anomaly_info = f"Time: {row['Time']}, Source: {row['Source']}, Destination: {row['Destination']}, Type: {row['Type']}, Reason: {anomaly_reason}"

        # Anomali tespit edildiğinde kullanıcıya bildirim göster
        alert_user(anomaly_info)

# Anomalileri göstermek için bir fonksiyon
def display_anomalies():
    text.delete(1.0, tk.END)
    
    if selected_protocol.get() == "":
        anomalies = df[df['Anomaly'] == -1]  # Tüm anomalileri göster
    else:
        anomalies = df[(df['Anomaly'] == -1) & (df['Type'] == selected_protocol.get())]  # Sadece filtrelenen protokolleri göster
    
    if anomalies.empty:
        text.insert(tk.END, "No anomalies found matching the filter criteria.\n")
    else:
        for index, row in anomalies.iterrows():
            anomaly_reason = detect_anomaly_reason(row)
            text.insert(tk.END, f"Time: {row['Time']}, Source: {row['Source']}, Destination: {row['Destination']}, "
                                f"Type: {row['Type']}, Reason: {anomaly_reason}\n")

# Anomali nedenini tespit eden bir fonksiyon
def detect_anomaly_reason(row):
    reasons = []
    if row['Length'] > df['Length'].quantile(0.99):
        reasons.append("Unusually large packet size")
    if row['Source Port'] > 65535 or row['Destination Port'] > 65535:
        reasons.append("Invalid port number")
    if not reasons:
        reasons.append("Unknown anomaly")
    return ', '.join(reasons)

# Anomali tespit edildiği taktirde kullanıcıya anlık bildirim verme
def alert_user(anomaly_info):
    if "reason: unknown anomaly" not in anomaly_info.lower():
        messagebox.showwarning("Anomaly Detected", f"Anomaly detected: {anomaly_info}")

# Anomali tespiti sonuçlarını görselleştiren bir fonksiyon (Pasta grafiği)
def visualize_anomalies():
    total_scans = len(df)
    total_anomalies = len(df[df['Anomaly'] == -1])

    labels = ['Normal', 'Anomalies']
    sizes = [total_scans - total_anomalies, total_anomalies]
    colors = ['#66b3ff', '#ff6666']

    plt.figure(figsize=(6,6))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title('Anomalies vs Normal Traffic')
    plt.show()

# Kullanıcı arayüzüne grafik gösterme butonu ekleme
button_visualize = tk.Button(root, text="Visualize Anomalies", command=visualize_anomalies)
button_visualize.pack()

# Sniffing işlemini durdurmak için bir fonksiyon
def stop_sniffing_action():
    stop_sniffing.set()  # Sniffing işlemini durdur
    print("Sniffing stopped.")

# Sniffing işlemini başlatmak için bir fonksiyon
def start_sniffing_action():
    stop_sniffing.clear()  # Sniffing işlemini yeniden başlat
    threading.Thread(target=start_sniffing).start()
    print("Sniffing started.")

# Ekrandaki çıktıları temizlemek için bir fonksiyon
def clear_output():
    text.delete(1.0, tk.END)

# Log dosyasını kaydetmek için bir fonksiyon
def save_log():
    global log_file_path
    log_file_path = simpledialog.askstring("Log File", "Enter log file name:")
    if log_file_path:
        if not log_file_path.endswith(".txt"):
            log_file_path += ".txt"
        with open(log_file_path, "w") as log_file:
            for index, row in df.iterrows():
                log_file.write(f"{row.to_dict()}\n")
        messagebox.showinfo("Log Saved", f"Log saved as {log_file_path}")

# Kullanıcı arayüzü öğeleri
text = tk.Text(root)
text.pack()

tk.Label(root, text="Source IP:").pack()
tk.Entry(root, textvariable=selected_src_ip).pack()

tk.Label(root, text="Destination IP:").pack()
tk.Entry(root, textvariable=selected_dst_ip).pack()

tk.Label(root, text="Protocol:").pack()
protocol_options = ["", "TCP", "UDP", "ICMP", "Other"]
selected_protocol.set(protocol_options[0])
tk.OptionMenu(root, selected_protocol, *protocol_options).pack()

button_show = tk.Button(root, text="Show Anomalies", command=display_anomalies)
button_show.pack()

button_clear = tk.Button(root, text="Clear Output", command=clear_output)
button_clear.pack()

button_stop = tk.Button(root, text="Stop", command=stop_sniffing_action)
button_stop.pack()

button_start = tk.Button(root, text="Start", command=start_sniffing_action)
button_start.pack()

button_save_log = tk.Button(root, text="Save Log", command=save_log)
button_save_log.pack()

# Veri çerçevesi ve model
columns = ['Time', 'Source', 'Destination', 'Source Port', 'Destination Port', 'Length', 'Type']
df = pd.DataFrame(columns=columns)

# Isolation Forest modelini oluşturma
model = IsolationForest(contamination=0.01)

# Tkinter ana döngüsünü çalıştırma
root.mainloop()
