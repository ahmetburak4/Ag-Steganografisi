#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Ağ Steganalizi: Shannon Entropisi Tabanlı Anomali Tespit Sistemi (IDS)

import math
from collections import Counter
from scapy.all import sniff, TCP

PENCERE_BOYUTU = 25
ENTROPI_ESIGI = 4.20  

son_isn_degerleri = []

def shannon_entropi_hesapla(veri_listesi):
    """Bir veri kümesinin Shannon Entropisini hesaplar"""
    if not veri_listesi:
        return 0
    
    sayac = Counter(veri_listesi)
    toplam_eleman = len(veri_listesi)
    
    entropi = 0.0
    for miktar in sayac.values():
        olasilik = miktar / toplam_eleman
        entropi -= olasilik * math.log2(olasilik)
        
    return entropi

def trafik_analizi(paket):
    """Paketleri inceler ve anomali tespiti yapar"""
    if paket.haslayer(TCP) and paket[TCP].flags == "S":
        veri_parcasi = paket[TCP].seq & 0xFFFFFF
        son_isn_degerleri.append(veri_parcasi)
        
        if len(son_isn_degerleri) > PENCERE_BOYUTU:
            son_isn_degerleri.pop(0)
            
        if len(son_isn_degerleri) == PENCERE_BOYUTU:
            guncel_entropi = shannon_entropi_hesapla(son_isn_degerleri)
            
            if guncel_entropi > ENTROPI_ESIGI:
                print(f"[!] KIRMIZI ALARM! ÖRTÜLÜ KANAL TESPİT EDİLDİ!")
                print(f"    - Entropi Puanı: {guncel_entropi:.2f} (Eşik: {ENTROPI_ESIGI})")
                print(f"    - Tehdit: Yüksek rastgeleliğe sahip şifreli veri sızıntısı şüphesi!\n")

if __name__ == "__main__":
    print("=====================================================")
    print("   ENTROPİ TABANLI AĞ STEGANALİZİ (IDS) BAŞLATILDI   ")
    print("=====================================================")
    print(f"[*] Ağ dinleniyor... (Eşik Değeri: {ENTROPI_ESIGI})")
    sniff(filter="tcp", prn=trafik_analizi)