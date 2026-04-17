import gzip
import json
import os
import pandas as pd
import joblib
import glob
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ==========================================
# --- KONFIGURACE A DEFINICE DAT ---
# ==========================================
# Základní složka, kde jsou uloženy Zeek logy
BASE_LOG_DIR = "/home/klugy/ARCHIVE" 

# Období, kdy na síti nebyla velká aktivita - slouží pro trénování "away" profilu
QUIET_DAYS = ["2026-03-06", "2026-03-07", "2026-03-08", "2026-03-09", "2026-03-10", "2026-03-11", "2026-03-12", "2026-03-13"] 
# Období s běžným provozem - slouží pro trénování "home" profilu
NORMAL_DAYS = ["2026-03-15", "2026-03-16", "2026-03-17", "2026-03-18", "2026-03-19", "2026-03-20", "2026-03-21", "2026-03-22"]

# ==========================================
# --- POMOCNÉ FUNKCE PRO NAČÍTÁNÍ DAT ---
# ==========================================
def load_zeek_logs(day_path, log_type):
    """
    Načte komprimované Zeek logy z formátu JSON do Pandas DataFrame.
    """
    # Vyhledání všech souborů odpovídajících danému typu logu (např. conn.*.log.gz)
    search_pattern = os.path.join(day_path, f"{log_type}.*.log.gz")
    files = glob.glob(search_pattern)
    
    # Pokud rotované logy neexistují, skript se pokusí najít hlavní (nerotovaný) soubor
    if not files:
        base_file = os.path.join(day_path, f"{log_type}.log.gz")
        if os.path.exists(base_file):
            files = [base_file]
    
    combined_data = []
    # Procházení všech nalezených gzip souborů a čtení po řádcích
    for file in files:
        try:
            with gzip.open(file, 'rt') as f:
                for line in f:
                    # Zeek logy mohou obsahovat hlavičky začínající '#', tyto řádky se ignorují
                    if line.startswith('#'): continue
                    combined_data.append(json.loads(line))
        except Exception as e:
            print(f"Chyba pri cteni {file}: {e}")
            
    return pd.DataFrame(combined_data)

# ==========================================
# --- EXTRAKCE A PŘÍPRAVA PŘÍZNAKŮ (FEATURES) ---
# ==========================================
def extract_features(day_folder):
    """
    Zpracuje surové logy z daného dne, převede je na časové řady s krokem 1 minuta
    a agreguje z nich síťové statistiky (počet bajtů, spojení, dotazů apod.).
    """
    path = os.path.join(BASE_LOG_DIR, day_folder)
    print(f"--- Agreguji data ze slozky: {day_folder} ---")
    
    # Načtení logů pro daný den
    df_conn = load_zeek_logs(path, "conn")
    df_dns = load_zeek_logs(path, "dns")
    df_http = load_zeek_logs(path, "http")
    df_ssl = load_zeek_logs(path, "ssl")

    # Pokud nejsou k dispozici žádná data o spojeních, funkce se ukončí
    if df_conn.empty: return None

    # Převod UNIX timestampu na čitelný datetime objekt (nutné pro resamplování)
    df_conn['ts'] = pd.to_datetime(df_conn['ts'], unit='s')
    df_conn['duration'] = pd.to_numeric(df_conn['duration'], errors='coerce').fillna(0)
    
    # Pro snadnější sumarizaci jsou hodnoty True/False převedeny na 1/0
    if 'proto' in df_conn.columns:
        df_conn['is_tcp'] = (df_conn['proto'] == 'tcp').astype(int)
        df_conn['is_udp'] = (df_conn['proto'] == 'udp').astype(int)
        df_conn['is_icmp'] = (df_conn['proto'] == 'icmp').astype(int)
    else:
        df_conn['is_tcp'] = df_conn['is_udp'] = df_conn['is_icmp'] = 0

    # Agregace dat po 1 minutě (vytváří se časová "okna" pro model)
    features = df_conn.resample('1Min', on='ts').agg({
        'orig_bytes': 'sum',       # Celkový odchozí provoz
        'resp_bytes': 'sum',       # Celkový příchozí provoz
        'id.resp_p': 'nunique',    # Počet unikátních cílových portů (indikátor skenování)
        'id.resp_h': 'nunique',    # Počet unikátních cílových IP (indikátor komunikace s mnoha servery)
        'is_tcp': 'sum',           # Počet TCP spojení
        'is_udp': 'sum',           # Počet UDP spojení
        'is_icmp': 'sum',          # Počet ICMP (ping) spojení
        'duration': 'mean'         # Průměrná délka spojení v dané minutě
    }).fillna(0) # Pokud v dané minutě neproběhla komunikace, hodnoty NaN se nahradí nulami

    # --- Připojení dat z ostatních logů (DNS, HTTP, SSL) ---
    # Data se spojují podle času ('ts') k hlavní tabulce 'features'

    if not df_dns.empty:
        df_dns['ts'] = pd.to_datetime(df_dns['ts'], unit='s')
        # Zjistí se počet DNS dotazů v každé minutě
        dns_res = df_dns.resample('1Min', on='ts').size().rename('dns_queries')
        features = features.join(dns_res).fillna(0)
    else:
        features['dns_queries'] = 0

    if not df_http.empty:
        df_http['ts'] = pd.to_datetime(df_http['ts'], unit='s')
        http_res = df_http.resample('1Min', on='ts').size().rename('http_count')
        features = features.join(http_res).fillna(0)
    else:
        features['http_count'] = 0

    if not df_ssl.empty:
        df_ssl['ts'] = pd.to_datetime(df_ssl['ts'], unit='s')
        ssl_res = df_ssl.resample('1Min', on='ts').size().rename('ssl_count')
        features = features.join(ssl_res).fillna(0)
    else:
        features['ssl_count'] = 0

    # Agregace HTTP a SSL do jedné metriky pro "webovou aktivitu" 
    # a následné odstranění původních sloupců pro čistší dataset
    features['web_activity'] = features['http_count'] + features['ssl_count']
    features = features.drop(columns=['http_count', 'ssl_count'])

    return features

# ==========================================
# --- TRÉNOVÁNÍ ML MODELU ---
# ==========================================
def train(days, mode_name):
    """
    Načte a spojí data z vybraných dnů, normalizuje je a vytrénuje model 
    IsolationForest pro detekci anomálií pro specifický režim (home/away).
    """
    all_dfs = []
    # Funkce projde všechny dny v dané konfiguraci a extrahuje příznaky
    for day in days:
        df = extract_features(day)
        if df is not None: all_dfs.append(df)
    
    # Ochrana proti prázdným datům
    if not all_dfs:
        print(f"Zadna data pro {mode_name}!")
        return

    # Sloučení všech denních DataFrame do jednoho velkého pro trénink
    full_df = pd.concat(all_dfs)
    full_df = full_df.fillna(0)
    
    print(f"Trenuji model pro rezim: {mode_name} (vzorku: {len(full_df)})")
    
    # --- Škálování dat ---
    # IsolationForest spoléhá na vzdálenosti v N-rozměrném prostoru. 
    # Bez škálování by např. 'orig_bytes' (v milionech) úplně převálcoval 'dns_queries' (v desítkách).
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(full_df)
    
    # --- Trénování modelu ---
    # n_estimators=150: Počet stromů v lese (čím více, tím stabilnější, ale pomalejší)
    # contamination=0.01: Předpokládá se, že cca 1 % trénovacích dat mohou být anomálie/šum
    model = IsolationForest(n_estimators=150, contamination=0.01, random_state=42)
    model.fit(scaled_data)
    
    # --- Ukládání výsledků (Serializace) ---
    # Je nutné uložit jak model, tak scaler, protože data pro predikci se musí škálovat naprosto stejně jako trénovací.
    # Ukládají se také názvy sloupců, aby se předešlo chybám v pořadí příznaků při predikci v reálném čase.
    joblib.dump(model, f"model_{mode_name}.pkl")
    joblib.dump(scaler, f"scaler_{mode_name}.pkl")
    joblib.dump(list(full_df.columns), f"columns_{mode_name}.pkl")
    
    print(f" Hotovo: model_{mode_name}.pkl a scaler_{mode_name}.pkl")
    print(f"Vygenerovane sloupce: {list(full_df.columns)}\n")

# ==========================================
# --- SPUŠTĚNÍ SKRIPTU ---
# ==========================================
if __name__ == "__main__":
    # Vytrénuje model pro situaci "nikdo není doma"
    train(QUIET_DAYS, "away")
    # Vytrénuje model pro situaci "běžný ruch v domácnosti"
    train(NORMAL_DAYS, "home")