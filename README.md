# Ag-Steganografisi

# Ağ Steganografisi ve Örtülü Kanallar (Network Steganography)

Bu proje, TCP/IP yığını üzerinde örtülü kanallar (covert channels) oluşturarak veri sızdırma ve bu tür sızıntıları istatistiksel entropi analizi ile tespit etme üzerine geliştirilmiş bir haberleşme güvenliği çalışmasıdır.

## 📌 Proje Hakkında
Geleneksel kriptografi verinin içeriğini gizlerken, ağ steganografisi iletişimin bizzat varlığını gizlemeyi amaçlar. Bu projede, Derin Paket İnceleme (DPI) sistemlerini ve güvenlik duvarlarını atlatabilmek amacıyla IPv4 Identification (ID) ve TCP Initial Sequence Number (ISN) alanları kullanılarak veri manipülasyonu gerçekleştirilmiştir.

**Öne Çıkan Özellikler:**
* **AES-128 Kriptografi:** Gömülecek veri yüksek entropili hale getirilerek "rastgelelik" taklit edilmiştir.
* **İleri Hata Düzeltme (FEC):** Ağ gürültüsüne (packet loss) karşı, bozulan paketler **Reed-Solomon** algoritması ile vericiden tekrar istenmeden havada onarılmaktadır.
* **Hayalet Modu (Jitter):** Zamanlama analizlerini atlatmak için paket gönderimlerine sözde-rastgele gecikmeler eklenmiştir.
* **Ağ Steganalizi (IDS):** Mavi takım perspektifiyle çalışan dinleyici modül, ağdaki paketlerin Shannon Entropisini ölçerek "fazla mükemmel" rastgeleliğe sahip şifreli trafikleri (Eşik: 4.20) tespit edebilmektedir.

## ⚙️ Kurulum ve Kullanım

### Gereksinimler
Projeyi çalıştırmak için Python 3.x ve aşağıdaki kütüphaneler gereklidir:
`pip install scapy cryptography reedsolo`

### Modüller
1. **`gonderici.py` (Red Team):** Hedef dosyayı okur, AES ile şifreler, RS eşlik bitlerini ekler ve TCP ISN kanalı üzerinden hedefe fırlatır.
2. **`alici.py` (Blue/Red Team):** Ağ arayüzünü pasif dinleme moduna alır. Sızdırılan paketleri yakalar, ağ gürültüsünü onarır ve şifreyi çözerek orijinal dosyayı inşa eder.
3. **`tespit_sistemi.py` (IDS):** Ağ üzerinde steganografik anomali tespiti yapar.

## ⚠️ Yasal Uyarı
Bu proje tamamen **akademik araştırma ve eğitim** amacıyla geliştirilmiştir. Siber güvenlik farkındalığını artırmak ve savunma mekanizmaları (Blue Team) geliştirmek hedeflenmiştir. Gerçek ve yetkisiz ağlar üzerinde kullanılması yasa dışıdır. Tüm sorumluluk kullanıcıya aittir.
