
---

## 🟦 Ağ Trafiği İzleme ve Anomali Tespit Sistemi

```markdown
# 🌐 Ağ Trafiği İzleme ve Anomali Tespit Sistemi

Bu proje, gerçek zamanlı ağ trafiğini izleyen ve anormal davranışları tespit eden bir sistemdir. Python, Scapy ve Isolation Forest algoritması kullanılarak paket bazlı analiz yapılır. Tkinter arayüzü ile kullanıcı dostu bir deneyim sunar.

## 🚀 Özellikler

- 🔍 Gerçek zamanlı paket yakalama ve izleme
- ⚠️ Anomali tespiti (örneğin: anormal paket boyutu, geçersiz port kullanımı)
- 📋 Filtreleme: IP adresi, protokol türü
- 📊 Anomali görselleştirme (pie chart)
- 🧾 Log kaydı oluşturma ve dışa aktarma

## 🛠️ Kullanılan Teknolojiler

- Python 3.x  
- [Scapy](https://scapy.net/) – Ağ paketi yakalama  
- Tkinter – GUI (kullanıcı arayüzü)  
- Scikit-learn (Isolation Forest) – Anomali tespiti  
- Matplotlib – Görselleştirme  
- Pandas – Veri işleme

## 🖼️ Arayüzden Görüntü

> Aşağıdaki arayüz öğeleri mevcuttur:  
> - Protokol/IP filtreleme  
> - Anomali listeleme  
> - Anlık uyarı mesajı  
> - Log dosyasını dışa aktarma

## 📁 Dosya Yapısı
  - UDHproje.py
  - network_traffic_log.txt
  - README.md


## ⚙️ Kurulum

  git clone https://github.com/kullaniciadi/network-anomaly-monitor.git
  cd network-anomaly-monitor
  pip install scapy pandas matplotlib scikit-learn

## 🔧 Kullanım
  python UDHproje.py

-  Start butonu ile ağ taraması başlar.

-  Filtreleme seçenekleri (IP, protokol) kullanılabilir.

-  Anomaliler tespit edildiğinde arayüzde uyarı verir.

-  Visualize Anomalies butonuyla istatistiksel analiz yapılabilir.

## 💡 Örnek Anomali Kriterleri
-  Paket boyutunun alışılmadık derecede büyük olması

-  Kaynak veya hedef portun geçersiz bir aralıkta olması

-  İstatistiksel olarak uç noktalarda yer alan davranışlar

## 🧪 Geliştirilebilir Alanlar
-  Daha gelişmiş model entegrasyonu (e.g., AutoEncoder, One-Class SVM)

-  Veritabanı bağlantısı

-  Web tabanlı arayüz (Flask, FastAPI)
