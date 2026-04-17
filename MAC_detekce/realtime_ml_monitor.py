import os
import json
import time
import joblib
import pandas as pd
from datetime import datetime
from collections import defaultdict
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# ==========================================
# --- KONFIGURACE ---
# ==========================================
# Cesty k logům generovaným systémem Zeek
SPOOL_DIR = "/opt/zeek/spool/zeek"
# Soubor určující režim sítě (pokud existuje, síť je v režimu "away", jinak "home")
MODE_FILE = "/home/klugy/MAC_detekce/AWAY_MODE.lock" 

LOGS = {
    "conn": os.path.join(SPOOL_DIR, "conn.log"),
    "dns": os.path.join(SPOOL_DIR, "dns.log"),
    "http": os.path.join(SPOOL_DIR, "http.log"),
    "ssl": os.path.join(SPOOL_DIR, "ssl.log")
}

# Cesty k podpůrným souborům pro identifikaci zařízení a blokaci domén
WHITELIST_FILE = "/home/klugy/MAC_detekce/WhitelistMAC.csv"
VENDORS_FILE = "/home/klugy/MAC_detekce/mac-vendor.txt"
BANNED_DIR = "/home/klugy/MAC_detekce/Banned" 
ALERT_INTERVAL = 30 
ROUTER_IP = "192.168.69.254" 

# Nastavení připojení do časové databáze InfluxDB pro ukládání metrik a anomálií
INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "<VÁŠ_TOKEN>"
INFLUX_ORG = "home"
INFLUX_BUCKET = "zeek"

# ==========================================
# --- GLOBALNI STAVY A PAMET ---
# ==========================================
ts = datetime.now().strftime('%H:%M:%S')
print(f"[{ts}] [SYSTEM] Nacitam ML modely a scalery...")

# Načtení vytrénovaných modelů a objektů pro normalizaci dat (scalers)
models = {
    "home": joblib.load("model_home.pkl"),
    "away": joblib.load("model_away.pkl")
}
scalers = {
    "home": joblib.load("scaler_home.pkl"),
    "away": joblib.load("scaler_away.pkl")
}
# Načtení pořadí sloupců, aby vstupní data do modelu odpovídala datům při tréninku
feature_cols = joblib.load("columns_home.pkl") 

# Agregační slovníky pro strojové učení (resetují se každou minutu)
ml_stats = {
    "orig_bytes": 0, "resp_bytes": 0,
    "unique_ports": set(), "unique_ips": set(),
    "tcp": 0, "udp": 0, "icmp": 0,
    "dns_queries": 0, "web_activity": 0,
    "total_duration": 0.0, "duration_count": 0,
    "failed_conns": 0
}

# Kontextové slovníky pro uchovávání objemu přenesených dat a počtu spojení
ctx_bytes = {"ip": defaultdict(int), "dest_ips": defaultdict(int), "proto_port": defaultdict(int)}
ctx_count = {"ip": defaultdict(int), "dest_ips": defaultdict(int), "proto_port": defaultdict(int), "domains": defaultdict(int)}

# Proměnné specifické pro detekci port scanů a podezřelých aktivit
attacker_u_ports = defaultdict(set)
attacker_u_ips = defaultdict(set)
attacker_fails = defaultdict(int)

# Mapovací struktury pro propojení síťových entit
ip_to_mac = {}
ip_to_domain = {}
known_ip_mac_map = {}
arp_alert_cooldown = {}

# Struktury pro sledování přístupů na zakázané domény
banned_hits = defaultdict(int)
banned_domains_set = set()

# Uchovávání stavu načtených externích souborů
mac_state = {
    "whitelist": {}, "vendors": {},
    "last_mtime": 0, "last_reported": {}, "last_check": time.time()
}
banned_state = {"last_mtime": 0, "last_check": time.time()}

# ==========================================
# --- POMOCNE FUNKCE ---
# ==========================================
def load_whitelist():
    """
    Načte seznam povolených MAC adres ze souboru CSV a namapuje je na jména zařízení.
    """
    wl = {}
    try:
        df = pd.read_csv(WHITELIST_FILE, sep=';')
        # Dynamické vyhledání sloupce se jménem zařízení
        name_col = next((col for col in df.columns if col.lower() in ['name', 'device', 'zarizeni', 'nazev']), None)
        for _, row in df.iterrows():
            mac = str(row['MAC']).strip().lower()
            name = str(row[name_col]).strip() if name_col else "Zname zarizeni"
            wl[mac] = name
        return wl
    except Exception: return {}

def load_vendors():
    """
    Načte databázi výrobců síťových karet na základě OUI (prvních 6 znaků MAC adresy).
    """
    v_db = {}
    try:
        with open(VENDORS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                parts = line.split(maxsplit=1)
                if len(parts) == 2: v_db[parts[0].strip().lower()] = parts[1].strip()
        return v_db
    except Exception: return {}

def load_banned_domains():
    """
    Načte všechny textové soubory v adresáři Banned a vytvoří množinu zakázaných domén.
    Filtruje komentáře a speciální znaky, které se často vyskytují v ad-block listech.
    """
    b_set = set()
    if not os.path.exists(BANNED_DIR):
        os.makedirs(BANNED_DIR)
        print("Slozka Banned neexistovala, byla vytvorena.")
        return b_set
        
    for filename in os.listdir(BANNED_DIR):
        if filename.endswith(".txt"):
            filepath = os.path.join(BANNED_DIR, filename)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        d = line.strip().lower()
                        if not d or d.startswith('!') or d.startswith('#') or d.startswith('['):
                            continue
                        d = d.replace('||', '').split('^')[0].strip()
                        if d: b_set.add(d)
            except Exception as e:
                pass
                
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] Nacteno {len(b_set)} zakazanych domen.")
    return b_set

def get_banned_mtime():
    """
    Získá čas poslední úpravy nejnovějšího souboru ve složce zakázaných domén.
    Slouží k určení, zda je potřeba znovu načíst seznam domén.
    """
    if not os.path.exists(BANNED_DIR): return 0
    max_mtime = os.stat(BANNED_DIR).st_mtime
    for f in os.listdir(BANNED_DIR):
        if f.endswith(".txt"):
            max_mtime = max(max_mtime, os.stat(os.path.join(BANNED_DIR, f)).st_mtime)
    return max_mtime

def get_device_info(mac):
    """Vrátí jméno zařízení z whitelistu, nebo jeho výrobce, pokud není na whitelistu."""
    if mac in mac_state["whitelist"]: return mac_state["whitelist"][mac]
    return mac_state["vendors"].get(mac.replace(':', '')[:6], "Neznamy vyrobce")

def get_device_vendor(mac):
    """Vrátí výrobce na základě zadané MAC adresy."""
    return mac_state["vendors"].get(mac.replace(':', '')[:6], "Neznamy")

def check_files_update():
    """
    Pravidelně kontroluje (každé 2 sekundy), zda nedošlo ke změně ve whitelistu 
    nebo v adresáři zakázaných domén. Pokud ano, seznamy se aktualizují v paměti.
    """
    now = time.time()
    if now - mac_state["last_check"] > 2:
        try:
            current_mtime = os.path.getmtime(WHITELIST_FILE)
            if current_mtime > mac_state["last_mtime"]:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] Whitelist aktualizovan z disku")
                mac_state["whitelist"] = load_whitelist()
                mac_state["last_mtime"] = current_mtime
        except OSError: pass
        
        try:
            current_b_mtime = get_banned_mtime()
            if current_b_mtime > banned_state["last_mtime"]:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] Zmena ve slozce Banned! Aktualizuji seznam...")
                global banned_domains_set
                banned_domains_set = load_banned_domains()
                banned_state["last_mtime"] = current_b_mtime
        except OSError: pass
        
        mac_state["last_check"] = now

def get_current_mode(): 
    """Zjišťuje režim běhu skriptu (home/away) na základě existence zámkového souboru."""
    return "away" if os.path.exists(MODE_FILE) else "home"

def open_log_tail(filepath):
    """
    Otevře soubor pro čtení a přesune kurzor na jeho konec.
    Slouží k plynulému čtení nových logů (jako příkaz 'tail -f').
    """
    if not os.path.exists(filepath): return None
    f = open(filepath, 'r')
    f.seek(0, 2)
    return f

def check_banned(domain, ip):
    """
    Zkontroluje, zda požadovaná doména nebo její subdomény nejsou na seznamu zakázaných.
    Pokud je nalezena shoda, je zaznamenána pro pozdější vyhodnocení.
    """
    if not domain or not ip or ":" in ip: return
    domain = domain.lower().strip().rstrip('.')
    parts = domain.split('.')
    
    # Procházení od celé domény směrem ke kořenové (např. a.b.com -> b.com -> com)
    for i in range(len(parts)):
        sub = '.'.join(parts[i:])
        if sub in banned_domains_set:
            banned_hits[(ip, sub)] += 1
            break

# ==========================================
# --- ZPRACOVANI RADKU ---
# ==========================================
def process_line(log_type, line, write_api, mode):
    """
    Zpracovává jednotlivé řádky z logů Zeeku. Agreguje statistiky do paměti 
    a okamžitě vyhodnocuje zjevné anomálie (např. ARP Spoofing).
    """
    if line.startswith('#'): return
    try:
        data = json.loads(line)
        orig_h = data.get("id.orig_h", "")
        resp_h = data.get("id.resp_h", "")
        # Ignorují se IPv6 adresy
        if ":" in orig_h or ":" in resp_h:
            return

        # Filtrování zastaralých spojení (zpoždění větší než 10 minut se ignoruje)
        log_ts = data.get("ts")
        if log_ts:
            connection_end = log_ts + data.get("duration", 0)
            if (time.time() - connection_end) > 600:
                return

        # --- Zpracování spojení (conn.log) ---
        if log_type == "conn":
            mac = data.get("orig_l2_addr", "").lower()
            ip = orig_h
            
            # Detekce ARP Spoofingu: Kontrola, zda IP nezměnila MAC adresu
            if ip and ip != "unknown" and ip != ROUTER_IP and ip != "0.0.0.0" and mac:
                if ip in known_ip_mac_map:
                    if known_ip_mac_map[ip] != mac:
                        now = time.time()
                        if ip not in arp_alert_cooldown or (now - arp_alert_cooldown[ip]) > 60:
                            ts = datetime.now().strftime('%H:%M:%S')
                            old_mac = known_ip_mac_map[ip]
                            print(f"[{ts}] [{mode.upper()}] ANOMALIE: ARP Spoofing! IP {ip} zmenila MAC z {old_mac} na {mac}")
                            p = Point("anomaly_arp_spoof").tag("mode", mode).tag("mac", mac).tag("old_mac", old_mac).field("ip", ip)
                            write_api.write(bucket=INFLUX_BUCKET, record=p)
                            arp_alert_cooldown[ip] = now
                        known_ip_mac_map[ip] = mac
                else:
                    known_ip_mac_map[ip] = mac

            # Upozornění na neznámá zařízení (zařízení mimo whitelist)
            if mac and mac not in mac_state["whitelist"] and ip:
                now = time.time()
                if mac not in mac_state["last_reported"] or (now - mac_state["last_reported"][mac]) > ALERT_INTERVAL:
                    vendor = get_device_vendor(mac)
                    ts = datetime.now().strftime('%H:%M:%S')
                    print(f"[{ts}] [{mode.upper()}] ANOMALIE: Neznama MAC | MAC: {mac} ({vendor}) | IP: {ip}")
                    p = Point("anomaly_unknown_mac").tag("mode", mode).tag("mac", mac).tag("vendor", vendor).field("ip", ip)
                    write_api.write(bucket=INFLUX_BUCKET, record=p)
                    mac_state["last_reported"][mac] = now

            # Zaznamenání selhaných pokusů o spojení
            c_state = data.get("conn_state", "")
            if c_state in ["REJ", "S0", "S1", "OTHR"]: 
                ml_stats["failed_conns"] += 1
                if ip and ip != "unknown": 
                    attacker_fails[ip] += 1

            # Sčítání přenesených dat a trvání spojení
            o_bytes = data.get("orig_bytes", 0)
            r_bytes = data.get("resp_bytes", 0)
            total_bytes = o_bytes + r_bytes
            
            try: dur = float(data.get("duration", 0))
            except ValueError: dur = 0.0
            
            ml_stats["total_duration"] += dur
            ml_stats["duration_count"] += 1
            ml_stats["orig_bytes"] += o_bytes
            ml_stats["resp_bytes"] += r_bytes
            
            # Sčítání statistik o protokolech a unikátních cílech
            resp_p = data.get("id.resp_p")
            proto = data.get("proto", "")
            
            if resp_p: ml_stats["unique_ports"].add(resp_p)
            if resp_h: ml_stats["unique_ips"].add(resp_h)
            
            if proto == "tcp": ml_stats["tcp"] += 1
            elif proto == "udp": ml_stats["udp"] += 1
            elif proto == "icmp": ml_stats["icmp"] += 1
            
            # Přiřazování provozu ke konkrétním IP adresám
            if ip and ip != "unknown":
                ctx_bytes["ip"][ip] += total_bytes
                ctx_count["ip"][ip] += 1
                ip_to_mac[ip] = mac
                
                if resp_p: attacker_u_ports[ip].add(resp_p)
                if resp_h: attacker_u_ips[ip].add(resp_h)
                
            if resp_h:
                ctx_bytes["dest_ips"][resp_h] += total_bytes
                ctx_count["dest_ips"][resp_h] += 1
            if proto and resp_p:
                proto_port = f"{proto.upper()}/{resp_p}"
                ctx_bytes["proto_port"][proto_port] += total_bytes
                ctx_count["proto_port"][proto_port] += 1

        # --- Zpracování DNS provozu ---
        elif log_type == "dns":
            ml_stats["dns_queries"] += 1
            query = data.get("query")
            if query: 
                ctx_count["domains"][query] += 1
                check_banned(query, orig_h)
                # Mapování odpovědí (IP) zpět na dotazovanou doménu pro pozdější zobrazení
                for ans in data.get("answers", []):
                    if "." in ans and ":" not in ans: ip_to_domain[ans] = query
                
        # --- Zpracování webového provozu (HTTP/SSL) ---
        elif log_type in ["http", "ssl"]:
            ml_stats["web_activity"] += 1
            domain = data.get("host") or data.get("server_name")
            if domain:
                ctx_count["domains"][domain] += 1
                check_banned(domain, orig_h)
                if resp_h:
                    ip_to_domain[resp_h] = domain
            
    except json.JSONDecodeError: pass

# ==========================================
# --- HLAVNI SMYCKA ---
# ==========================================
def run_ml_monitor():
    """
    Hlavní běhová smyčka, která nepřetržitě čte data ze Zeek logů a v nastaveném 
    intervalu (každých 60 sekund) agreguje a vyhodnocuje data na možné anomálie.
    Výsledky se zasílají do databáze InfluxDB.
    """
    mac_state["whitelist"] = load_whitelist()
    mac_state["vendors"] = load_vendors()
    if os.path.exists(WHITELIST_FILE): mac_state["last_mtime"] = os.path.getmtime(WHITELIST_FILE)
    
    global banned_domains_set
    banned_domains_set = load_banned_domains()
    banned_state["last_mtime"] = get_banned_mtime()
    
    # Inicializace spojení s InfluxDB
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = client.write_api(write_options=SYNCHRONOUS)
    
    # Otevření sledovaných log souborů
    file_handles = {}
    for ltype, path in LOGS.items():
        fh = open_log_tail(path)
        if fh: file_handles[ltype] = fh
        
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] SITOVY MONITORING SPUSTEN...")
    
    last_eval_time = time.time()
    
    try:
        while True:
            current_time = time.time()
            data_read = False
            check_files_update()
            mode = get_current_mode()
            
            # Čtení aktuálních dat ze všech sledovaných souborů
            for ltype, path in LOGS.items():
                fh = file_handles.get(ltype)
                if fh:
                    try:
                        # Ošetření rotace logů (inode check)
                        current_inode = os.stat(path).st_ino
                        active_inode = os.fstat(fh.fileno()).st_ino
                        if current_inode != active_inode:
                            ts = datetime.now().strftime('%H:%M:%S')
                            print(f"[{ts}] [{mode.upper()}] UPOZORNENI: Detekovana pulnocni rotace logu ({ltype}). Ctu novy soubor.")
                            fh.close()
                            fh = open(path, 'r')
                            file_handles[ltype] = fh
                    except OSError: pass

                    line = fh.readline()
                    if line:
                        process_line(ltype, line, write_api, mode)
                        data_read = True
                else:
                    # Pokus o otevření souboru, pokud dříve neexistoval
                    new_fh = open_log_tail(path)
                    if new_fh: file_handles[ltype] = new_fh
            
            # Zamezení přetížení CPU při absenci nových logů
            if not data_read: time.sleep(0.1)
                
            # --- EVALUACE (KAŽDÝCH 60 SEKUND) ---
            if current_time - last_eval_time >= 60:
                # Výpočet celkových souhrnů za minutu
                total_conns = ml_stats["tcp"] + ml_stats["udp"] + ml_stats["icmp"]
                u_ports = len(ml_stats["unique_ports"])
                u_ips = len(ml_stats["unique_ips"])
                up_mb = round(ml_stats["orig_bytes"] / 1048576, 2)
                down_mb = round(ml_stats["resp_bytes"] / 1048576, 2)
                fail_ratio = ml_stats["failed_conns"] / total_conns if total_conns > 0 else 0

                # Identifikace nejaktivnějšího klienta podle objemu dat
                top_ip_bytes = max(ctx_bytes["ip"], key=ctx_bytes["ip"].get) if ctx_bytes["ip"] else "N/A"
                top_dest_bytes = max(ctx_bytes["dest_ips"], key=ctx_bytes["dest_ips"].get) if ctx_bytes["dest_ips"] else "N/A"
                top_svc_bytes = max(ctx_bytes["proto_port"], key=ctx_bytes["proto_port"].get) if ctx_bytes["proto_port"] else "N/A"
                mac_bytes = ip_to_mac.get(top_ip_bytes, "")
                dev_bytes = get_device_info(mac_bytes)
                dom_bytes = ip_to_domain.get(top_dest_bytes, "Zadna")

                # Identifikace nejaktivnějšího klienta podle počtu spojení
                top_ip_conns = max(ctx_count["ip"], key=ctx_count["ip"].get) if ctx_count["ip"] else "N/A"
                top_dest_conns = max(ctx_count["dest_ips"], key=ctx_count["dest_ips"].get) if ctx_count["dest_ips"] else "N/A"
                top_svc_conns = max(ctx_count["proto_port"], key=ctx_count["proto_port"].get) if ctx_count["proto_port"] else "N/A"
                conns_max = ctx_count["ip"].get(top_ip_conns, 0)
                mac_conns = ip_to_mac.get(top_ip_conns, "")
                dev_conns = get_device_info(mac_conns)
                dom_conns = ip_to_domain.get(top_dest_conns, "Zadna")
                
                # Identifikace potenciálního útočníka (založeno na selhaných pokusech) pro odhalení nenápadných scanů
                top_attacker_ip = max(attacker_fails, key=attacker_fails.get) if attacker_fails else top_ip_conns
                atk_ports = len(attacker_u_ports[top_attacker_ip]) if top_attacker_ip in attacker_u_ports else 0
                atk_ips = len(attacker_u_ips[top_attacker_ip]) if top_attacker_ip in attacker_u_ips else 0
                atk_conns = ctx_count["ip"].get(top_attacker_ip, 0)
                atk_fails = attacker_fails.get(top_attacker_ip, 0)
                atk_fail_ratio = atk_fails / atk_conns if atk_conns > 0 else 0
                atk_mac = ip_to_mac.get(top_attacker_ip, "")
                atk_dev = get_device_info(atk_mac)

                anomalies_detected = []

                # 1. NADMERNY PRENOS DAT (Heuristické pravidlo)
                if up_mb > 50 or down_mb > 100:
                    anomalies_detected.append({
                        "table": "anomaly_high_traffic", "label": "Nadmerny datovy prenos",
                        "ip": top_ip_bytes, "mac": mac_bytes, "dev": dev_bytes, "dest": top_dest_bytes, "svc": top_svc_bytes, "dom": dom_bytes,
                        "extra": f"[Down: {down_mb}MB, Up: {up_mb}MB]", "up": up_mb, "down": down_mb,
                        "value_key": "total_mb", "value_val": up_mb + down_mb
                    })

                # 2. PORT SCAN / SWEEP (Vyhodnocuje pouze chování "top_attacker_ip")
                if top_attacker_ip != "N/A" and top_attacker_ip != ROUTER_IP:
                    # Detekce agresivních skenů (vysoký počet portů a velký poměr selhání)
                    if (atk_ports > 300 and atk_fail_ratio > 0.4) or (atk_ports > 500 and atk_fail_ratio > 0.2):
                        lbl = "Plosny Port Scan (Subnet)" if atk_ips > 5 else "Cileny Port Scan (1 IP)"
                        anomalies_detected.append({
                            "table": "anomaly_port_scan", "label": lbl,
                            "ip": top_attacker_ip, "mac": atk_mac, "dev": atk_dev,
                            "dest": f"Subnet ({atk_ips} IP)" if atk_ips > 5 else top_dest_conns, 
                            "svc": f"Vice portu ({atk_ports})", "dom": "Zadna",
                            "extra": f"({atk_conns} spojeni, Fail: {round(atk_fail_ratio*100)}%)",
                            "value_key": "connections", "value_val": atk_conns
                        })
                    # Detekce Network Sweepů (pohyb po síti)
                    elif atk_ips > 20 and atk_ports <= 20 and atk_fail_ratio > 0.3:
                        # Ignorování běžného hlučného provozu (P2P, lokální discovery apod.)
                        noisy_ports = ["7680", "9993", "137", "138", "1900", "5353", 443, 53, 80]
                        if not any(str(p) in str(top_svc_conns) for p in noisy_ports):
                            anomalies_detected.append({
                                "table": "anomaly_port_scan", "label": "Network Sweep (Horizontalni)",
                                "ip": top_attacker_ip, "mac": atk_mac, "dev": atk_dev,
                                "dest": f"Subnet ({atk_ips} IP)", "svc": top_svc_conns, "dom": "Zadna",
                                "extra": f"({atk_conns} spojeni, Fail: {round(atk_fail_ratio*100)}%)",
                                "value_key": "connections", "value_val": atk_conns
                            })

                # 3. ZAKAZANE DOMENY
                if banned_hits:
                    for (b_ip, b_dom), b_count in banned_hits.items():
                        b_mac = ip_to_mac.get(b_ip, "")
                        b_dev = get_device_info(b_mac)
                        anomalies_detected.append({
                            "table": "anomaly_banned_domain", "label": "Zakazana domena",
                            "ip": b_ip, "mac": b_mac, "dev": b_dev,
                            "dest": "DNS/Web", "svc": "N/A", "dom": b_dom,
                            "extra": f"{b_count} pokus/y", "value_key": "connections", "value_val": b_count
                        })
                    banned_hits.clear()

                # 4. ML DETEKCE (Zhodnocení celkového minutového provozu vytrénovaným modelem)
                avg_duration = ml_stats["total_duration"] / ml_stats["duration_count"] if ml_stats["duration_count"] > 0 else 0.0
                vec_df = pd.DataFrame([{col: val for col, val in zip(feature_cols, [
                    ml_stats["orig_bytes"], ml_stats["resp_bytes"], u_ports, u_ips, 
                    ml_stats["tcp"], ml_stats["udp"], ml_stats["icmp"], 
                    ml_stats["dns_queries"], ml_stats["web_activity"], avg_duration
                ])}])
                
                vec_scaled = scalers[mode].transform(vec_df)
                
                # Model vrací -1 v případě anomálie
                if models[mode].predict(vec_scaled)[0] == -1:
                    already_caught = any(a["table"] == "anomaly_high_traffic" for a in anomalies_detected)
                    if not already_caught:
                        # Filtr drobných ML záškubů - k vyhlášení poplachu musí být splněny dodatečné podmínky
                        if (up_mb + down_mb > 0.7) or (u_ips > 30) or (fail_ratio > 0.4):
                            
                            # Logika pro výběr konkrétního zařízení zodpovědného za detekovanou anomálii
                            share_conns = conns_max / total_conns if total_conns > 0 else 0
                            total_bytes = ml_stats["orig_bytes"] + ml_stats["resp_bytes"]
                            share_bytes = ctx_bytes["ip"].get(top_ip_bytes, 0) / total_bytes if total_bytes > 0 else 0
                            
                            # Rozhodování, zda je pachatelem zařízení s nejvíce spojeními, nebo s největším datovým tokem
                            if share_bytes > (share_conns - 0.2) and (up_mb + down_mb) > 1.0:
                                ml_ip, ml_mac, ml_dev = top_ip_bytes, mac_bytes, dev_bytes
                                ml_dest, ml_svc, ml_dom = top_dest_bytes, top_svc_bytes, dom_bytes
                            else:
                                ml_ip, ml_mac, ml_dev = top_ip_conns, mac_conns, dev_conns
                                ml_dest, ml_svc, ml_dom = top_dest_conns, top_svc_conns, dom_conns

                            ml_extra_info = f"| Spojeni: {total_conns} | Unikatni IP: {u_