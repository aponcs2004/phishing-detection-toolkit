from urllib.parse import urlparse
import json
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).parent


def load_rules(config_path="rules.json"):
    with open(BASE_DIR / config_path, "r") as file:
        return json.load(file)


def classify_risk(score):
    if score >= 30:
        return "HIGH RISK - Likely phishing"
    elif score >= 15:
        return "MEDIUM RISK - Suspicious"
    else:
        return "LOW RISK - Probably safe"


def analyze_url(url, rules):
    parsed = urlparse(url)
    score = 0
    findings = []

    for rule in rules:
        triggered = False

        if rule["type"] == "protocol" and parsed.scheme == rule["value"]:
            triggered = True

        elif rule["type"] == "keyword":
            if any(word in url.lower() for word in rule["keywords"]):
                triggered = True

        elif rule["type"] == "length" and len(url) > rule["threshold"]:
            triggered = True

        elif rule["type"] == "subdomain" and parsed.netloc.count(".") > rule["threshold"]:
            triggered = True

        if triggered:
            score += rule["score"]
            findings.append({
                "rule": rule["name"],
                "score": rule["score"],
                "message": rule.get("message", "Suspicious indicator detected")
            })

    return {
        "url": url,
        "scheme": parsed.scheme,
        "domain": parsed.netloc,
        "path": parsed.path if parsed.path else "/",
        "score": score,
        "risk": classify_risk(score),
        "findings": findings,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def save_to_log(result, log_file="log.txt"):
    log_path = BASE_DIR / log_file

    with open(log_path, "a") as file:
        file.write(
            f"{result['timestamp']} | {result['url']} | "
            f"{result['risk']} | Score: {result['score']}\n"
        )


def check_adaptive_warning(log_file="log.txt"):
    log_path = BASE_DIR / log_file

    if not log_path.exists():
        return

    with open(log_path, "r") as file:
        high_risk_count = sum(1 for line in file if "HIGH RISK" in line)

    if high_risk_count >= 3:
        print("\nADAPTIVE WARNING:")
        print("Repeated exposure to high-risk URLs detected.")
        print("Please be extra cautious when visiting suspicious websites.")


def print_scan_report(result):
    print("\n" + "=" * 58)
    print("        PHISHING AWARENESS DETECTION TOOLKIT")
    print("=" * 58)
    print(f"Scan time:       {result['timestamp']}")
    print(f"URL scanned:     {result['url']}")
    print(f"Protocol:        {result['scheme']}")
    print(f"Domain:          {result['domain']}")
    print(f"Path:            {result['path']}")
    print("-" * 58)
    print(f"Risk score:      {result['score']}")
    print(f"Classification:  {result['risk']}")
    print("-" * 58)

    if result["findings"]:
        print("Triggered indicators:")
        for item in result["findings"]:
            print(f"  - {item['rule']} (+{item['score']})")
            print(f"    {item['message']}")
    else:
        print("Triggered indicators:")
        print("  - No suspicious indicators were detected.")

    print("=" * 58)


def evaluate_dataset(file_path="dataset.txt"):
    rules = load_rules()
    file_path = BASE_DIR / file_path

    TP = FP = TN = FN = 0

    with open(file_path, "r") as f:
        lines = f.readlines()

    for line in lines:
        url, actual = line.strip().split(",")

        result = analyze_url(url, rules)
        predicted = "phishing" if result["score"] >= 30 else "legit"

        if predicted == "phishing" and actual == "phishing":
            TP += 1
        elif predicted == "phishing" and actual == "legit":
            FP += 1
        elif predicted == "legit" and actual == "legit":
            TN += 1
        elif predicted == "legit" and actual == "phishing":
            FN += 1

    accuracy = (TP + TN) / (TP + TN + FP + FN)
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0

    print("\n" + "=" * 58)
    print("              DATASET EVALUATION RESULTS")
    print("=" * 58)
    print(f"True Positives:   {TP}")
    print(f"False Positives:  {FP}")
    print(f"True Negatives:   {TN}")
    print(f"False Negatives:  {FN}")
    print("-" * 58)
    print(f"Accuracy:         {round(accuracy * 100, 2)}%")
    print(f"Precision:        {round(precision * 100, 2)}%")
    print(f"Recall:           {round(recall * 100, 2)}%")
    print("=" * 58)


if __name__ == "__main__":
    while True:
        print("\nPHISHING AWARENESS DETECTION TOOLKIT")
        print("1. Evaluate dataset")
        print("2. Scan single URL")
        print("3. Exit")

        choice = input("\nSelect option (1, 2 or 3): ")

        if choice == "1":
            evaluate_dataset()

        elif choice == "2":
            rules = load_rules()
            url = input("\nEnter URL to scan: ")

            result = analyze_url(url, rules)

            print_scan_report(result)

            save_to_log(result)

            print("\nScan saved to behaviour log.")

            check_adaptive_warning()

        elif choice == "3":
            print("\nExiting toolkit.")
            break

        else:
            print("\nInvalid option. Please choose 1, 2 or 3.")
