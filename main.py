import os
import json
import time
import requests
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from dotenv import load_dotenv

load_dotenv()

VT_API = os.getenv("VT_API_KEY")
VULNERS_API = os.getenv("VULNERS_API_KEY")

if not VT_API or not VULNERS_API:
    raise ValueError("API ключи не найдены. Проверьте файл .env")

THREATS = []


# =========================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =========================================

def add_threat(threat_type, source, source_ip, description, severity="medium"):
    """Добавляет найденную угрозу в общий список."""
    THREATS.append({
        "type": threat_type,
        "source": source,
        "source_ip": source_ip,
        "description": description,
        "severity": severity
    })


def safe_get(url, headers=None, params=None, timeout=15):
    """Безопасный GET-запрос с обработкой ошибок."""
    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Ошибка GET-запроса: {e}")
        return None


def safe_post(url, headers=None, json_data=None, timeout=15):
    """Безопасный POST-запрос с обработкой ошибок."""
    try:
        response = requests.post(url, headers=headers, json=json_data, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Ошибка POST-запроса: {e}")
        return None


# =========================================
# ЗАГРУЗКА DEMO ЛОГОВ
# =========================================

def load_demo_logs(filename="demo_logs.json"):
    """Загружает demo-логи из JSON-файла."""
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Файл {filename} не найден")

    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    winevent_df = pd.DataFrame(data.get("winevent", []))
    dns_df = pd.DataFrame(data.get("dns", []))
    http_df = pd.DataFrame(data.get("http", []))

    return winevent_df, dns_df, http_df


# =========================================
# АНАЛИЗ WINDOWS EVENT LOGS
# =========================================

def analyze_windows_logs(winevent_df):
    """Анализирует события Windows и выделяет подозрительные Event ID."""
    if winevent_df.empty:
        return

    suspicious_ids = {4625, 1102, 4720, 4648}

    for _, row in winevent_df.iterrows():
        event_id = row.get("event_id")
        source_ip = row.get("source_ip", "N/A")
        description = row.get("description", "Нет описания")
        count = row.get("count", 1)

        if event_id in suspicious_ids:
            severity = "high" if event_id in [1102, 4720] else "medium"

            if event_id == 4625 and count >= 3:
                severity = "high"

            add_threat(
                threat_type="Windows Event",
                source="winevent",
                source_ip=source_ip,
                description=f"Event ID {event_id}: {description}, count={count}",
                severity=severity
            )


# =========================================
# АНАЛИЗ DNS ЛОГОВ
# =========================================

def check_domain_virustotal(domain):
    """Проверяет домен через VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API}

    data = safe_get(url, headers=headers)
    if not data:
        return None

    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0), stats
    except (KeyError, TypeError):
        return None


def analyze_dns_logs(dns_df):
    """Анализирует DNS-логи: объём, аномальные имена, вредоносные домены."""
    if dns_df.empty:
        return

    for _, row in dns_df.iterrows():
        query = str(row.get("query", "")).strip()
        src_ip = row.get("src_ip", "N/A")
        count = row.get("count", 0)

        if count > 20:
            add_threat(
                threat_type="DNS High Volume",
                source="dns",
                source_ip=src_ip,
                description=f"Частые DNS-запросы к {query}, count={count}",
                severity="medium"
            )

        suspicious_patterns = [
            len(query) > 25,
            "." not in query and count > 5,
            query.isupper()
        ]

        if any(suspicious_patterns):
            add_threat(
                threat_type="Suspicious DNS Query",
                source="dns",
                source_ip=src_ip,
                description=f"Подозрительный DNS-запрос: {query}",
                severity="high"
            )

        if "." in query and " " not in query:
            result = check_domain_virustotal(query)
            time.sleep(1)  # чтобы не упереться в rate limit API

            if result:
                malicious_count, _ = result
                if malicious_count > 0:
                    add_threat(
                        threat_type="Malicious Domain",
                        source="VirusTotal",
                        source_ip=src_ip,
                        description=f"Домен {query} помечен как вредоносный ({malicious_count} detections)",
                        severity="high"
                    )


# =========================================
# АНАЛИЗ HTTP ЛОГОВ
# =========================================

def analyze_http_logs(http_df):
    """Анализирует HTTP-логи на признаки сканирования и доступа к чувствительным путям."""
    if http_df.empty:
        return

    for _, row in http_df.iterrows():
        src_ip = row.get("src_ip", "N/A")
        method = row.get("method", "")
        url = row.get("url", "")
        status = row.get("status", "")
        user_agent = str(row.get("user_agent", "")).lower()

        if "sqlmap" in user_agent:
            add_threat(
                threat_type="Web Attack Tool",
                source="http",
                source_ip=src_ip,
                description=f"Обнаружен sqlmap: {method} {url}, status={status}",
                severity="high"
            )

        if "nikto" in user_agent:
            add_threat(
                threat_type="Web Scanner",
                source="http",
                source_ip=src_ip,
                description=f"Обнаружен Nikto: {method} {url}, status={status}",
                severity="high"
            )

        if "/admin" in url or "/wp-admin" in url:
            add_threat(
                threat_type="Sensitive Path Access",
                source="http",
                source_ip=src_ip,
                description=f"Доступ к чувствительному пути: {url}",
                severity="medium"
            )


# =========================================
# АНАЛИЗ ЛОГОВ SURICATA
# =========================================

def load_suricata_logs(filename="suricata_eve.json"):
    if not os.path.exists(filename):
        print(f"[WARNING] Файл {filename} не найден. Анализ Suricata будет пропущен.")
        return pd.DataFrame()

    try:
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read().strip()

        # Если файл начинается с [, значит это JSON-массив
        if content.startswith("["):
            data = json.loads(content)
            if isinstance(data, list):
                return pd.DataFrame(data)
            else:
                print("[WARNING] JSON не является списком записей.")
                return pd.DataFrame()

        # Иначе считаем, что это JSON Lines
        records = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"[WARNING] Пропущена некорректная строка Suricata: {line[:80]}")

        return pd.DataFrame(records)

    except Exception as e:
        print(f"[ERROR] Ошибка чтения логов Suricata: {e}")
        return pd.DataFrame()

def analyze_suricata_logs(suricata_df):
    """Анализирует alert, flow и dns события Suricata."""
    if suricata_df.empty:
        return

    if "event_type" not in suricata_df.columns:
        print("[WARNING] В логах Suricata отсутствует поле event_type")
        return

    alerts_df = suricata_df[suricata_df["event_type"] == "alert"]

    if not alerts_df.empty:
        for _, row in alerts_df.iterrows():
            src_ip = row.get("src_ip", "N/A")
            dest_ip = row.get("dest_ip", "N/A")
            alert = row.get("alert", {})
            alert = alert if isinstance(alert, dict) else {}

            signature = alert.get("signature", "Неизвестная сигнатура")
            severity_num = alert.get("severity", 3)

            severity = "high" if severity_num == 1 else "medium"
            if any(word in signature.lower() for word in ["trojan", "malware", "exploit", "sql injection"]):
                severity = "high"

            add_threat(
                threat_type="Suricata Alert",
                source="suricata",
                source_ip=src_ip,
                description=f"{signature} -> {dest_ip}",
                severity=severity
            )

    flow_df = suricata_df[suricata_df["event_type"] == "flow"]

    if not flow_df.empty:
        for _, row in flow_df.iterrows():
            src_ip = row.get("src_ip", "N/A")
            dest_ip = row.get("dest_ip", "N/A")
            proto = row.get("proto", "N/A")
            flow = row.get("flow", {})
            flow = flow if isinstance(flow, dict) else {}

            bytes_toserver = flow.get("bytes_toserver", 0)
            bytes_toclient = flow.get("bytes_toclient", 0)

            if bytes_toserver > 100000 or bytes_toclient > 100000:
                add_threat(
                    threat_type="Large Network Flow",
                    source="suricata",
                    source_ip=src_ip,
                    description=(
                        f"Крупный сетевой поток {src_ip} -> {dest_ip}, "
                        f"proto={proto}, toserver={bytes_toserver}, toclient={bytes_toclient}"
                    ),
                    severity="medium"
                )

    dns_df = suricata_df[suricata_df["event_type"] == "dns"]

    if not dns_df.empty and "src_ip" in dns_df.columns:
        grouped = dns_df.groupby("src_ip").size().sort_values(ascending=False)

        for src_ip, count in grouped.items():
            if count >= 5:
                add_threat(
                    threat_type="Suricata DNS Burst",
                    source="suricata",
                    source_ip=src_ip,
                    description=f"Повышенная DNS-активность по данным Suricata: {count} событий",
                    severity="medium"
                )


# =========================================
# АНАЛИЗ УЯЗВИМОСТЕЙ ЧЕРЕЗ VULNERS
# =========================================

def analyze_vulners():
    """Получает информацию об уязвимостях через Vulners API."""
    url = "https://vulners.com/api/v3/search/lucene/"
    headers = {
        "X-Api-Key": VULNERS_API,
        "Content-Type": "application/json"
    }
    payload = {
        "query": "apache",
        "skip": 0,
        "size": 5
    }

    data = safe_post(url, headers=headers, json_data=payload)
    if not data:
        return

    search_results = None

    if isinstance(data, dict):
        if "data" in data and isinstance(data["data"], dict):
            search_results = data["data"].get("search")
        if search_results is None and "search" in data:
            search_results = data.get("search")

    if not search_results:
        print("[WARNING] Vulners не вернул результатов или структура ответа отличается от ожидаемой.")
        return

    for item in search_results:
        source = item.get("_source", {}) if isinstance(item, dict) else {}
        title = source.get("title", "Без названия")

        cvss_data = source.get("cvss", {})
        if isinstance(cvss_data, dict):
            cvss = cvss_data.get("score", 0)
        else:
            cvss = 0

        if cvss >= 7:
            add_threat(
                threat_type="High CVSS Vulnerability",
                source="Vulners",
                source_ip="N/A",
                description=f"{title} (CVSS={cvss})",
                severity="high"
            )


# =========================================
# РЕАГИРОВАНИЕ
# =========================================

def respond_to_threats():
    """Выводит список угроз и имитирует реагирование."""
    print("\n=== ОБНАРУЖЕННЫЕ УГРОЗЫ ===")

    if not THREATS:
        print("Угроз не обнаружено.")
        return

    for threat in THREATS:
        print(
            f"[ALERT] [{threat['severity'].upper()}] "
            f"{threat['type']} | {threat['source_ip']} | {threat['description']}"
        )

        if threat["source_ip"] != "N/A":
            print(f"[ACTION] Имитация блокировки IP: {threat['source_ip']}")
        else:
            print("[ACTION] Требуется дополнительная проверка уязвимости")


# =========================================
# ОТЧЁТЫ
# =========================================

def save_report(filename="report.csv"):
    """Сохраняет CSV-отчёт."""
    df = pd.DataFrame(THREATS)

    if df.empty:
        print("[INFO] Нет данных для сохранения отчёта.")
        return

    df.insert(0, "incident_id", range(1, len(df) + 1))

    severity_order = {"high": 3, "medium": 2, "low": 1}
    df["severity_score"] = df["severity"].map(severity_order).fillna(0)

    df = df.sort_values(by=["severity_score", "type"], ascending=[False, True])

    df_to_save = df.drop(columns=["severity_score"])
    df_to_save.to_csv(filename, index=False, encoding="utf-8-sig")

    print(f"\n[INFO] Расширенный отчёт сохранён: {filename}")


def save_json_report(filename="report.json"):
    """Сохраняет JSON-отчёт."""
    if not THREATS:
        print("[INFO] Нет данных для сохранения JSON-отчёта.")
        return

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(THREATS, f, ensure_ascii=False, indent=4)

    print(f"[INFO] JSON-отчёт сохранён: {filename}")


# =========================================
# ГРАФИКИ
# =========================================

def save_charts():
    """Строит и сохраняет графики по найденным угрозам."""
    df = pd.DataFrame(THREATS)

    if df.empty:
        print("[INFO] Нет данных для построения графиков.")
        return

    sns.set_theme(style="whitegrid")

    # 1. Распределение типов угроз
    plt.figure(figsize=(11, 6))
    type_counts = df["type"].value_counts()
    ax = sns.barplot(x=type_counts.index, y=type_counts.values)
    ax.set_title("Распределение типов угроз")
    ax.set_xlabel("Тип угрозы")
    ax.set_ylabel("Количество")
    plt.xticks(rotation=45, ha="right")
    
    # Добавляем точные значения на столбцы
    for i, v in enumerate(type_counts.values):
        ax.text(i, v, str(int(v)), ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig("threat_statistics.png", dpi=300)
    plt.close()
    print("[INFO] График сохранён: threat_statistics.png")

    # 2. Распределение по severity
    plt.figure(figsize=(8, 5))
    severity_counts = df["severity"].value_counts().reindex(["high", "medium", "low"]).fillna(0)
    ax = sns.barplot(x=severity_counts.index, y=severity_counts.values)
    ax.set_title("Распределение угроз по критичности")
    ax.set_xlabel("Критичность")
    ax.set_ylabel("Количество")
    
    # Добавляем точные значения на столбцы
    for i, v in enumerate(severity_counts.values):
        ax.text(i, v, str(int(v)), ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig("severity_statistics.png", dpi=300)
    plt.close()
    print("[INFO] График сохранён: severity_statistics.png")

    # 3. Top 5 IP
    top_ips = df[df["source_ip"] != "N/A"]["source_ip"].value_counts().head(5)

    if not top_ips.empty:
        plt.figure(figsize=(10, 5))
        ax = sns.barplot(x=top_ips.index, y=top_ips.values)
        ax.set_title("Top-5 IP-адресов по числу инцидентов")
        ax.set_xlabel("IP-адрес")
        ax.set_ylabel("Количество инцидентов")
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()
        plt.savefig("top_ip_threats.png", dpi=300)
        plt.close()
        print("[INFO] График сохранён: top_ip_threats.png")


# =========================================
# MAIN
# =========================================

def main():
    print("[INFO] Загрузка demo логов...")
    winevent_df, dns_df, http_df = load_demo_logs("demo_logs.json")

    print("[INFO] Анализ Windows логов...")
    analyze_windows_logs(winevent_df)

    print("[INFO] Анализ DNS логов...")
    analyze_dns_logs(dns_df)

    print("[INFO] Анализ HTTP логов...")
    analyze_http_logs(http_df)

    print("[INFO] Загрузка логов Suricata...")
    suricata_df = load_suricata_logs("suricata_eve.json")

    print("[INFO] Анализ логов Suricata...")
    analyze_suricata_logs(suricata_df)

    print("[INFO] Анализ уязвимостей через Vulners...")
    analyze_vulners()

    respond_to_threats()
    save_report("report.csv")
    save_json_report("report.json")
    save_charts()

    print("\n[INFO] Анализ завершён успешно.")


if __name__ == "__main__":
    THREATS.clear()
    main()