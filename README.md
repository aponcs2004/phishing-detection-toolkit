# phishing-detection-toolkit
A Python-based cybersecurity toolkit developed to analyse URLs and identify potential phishing threats using a transparent rule-based detection system. The project was created as a final-year Computer Science dissertation project focused on phishing awareness, explainability, and user-focused cybersecurity. The toolkit evaluates URLs against multiple phishing indicators including insecure HTTP usage, suspicious keywords, excessive URL length, and abnormal subdomain structures.

The system uses configurable phishing detection rules stored in an external JSON file, allowing the toolkit to remain modular, scalable, and easy to extend without modifying the main codebase. A weighted scoring mechanism classifies URLs into LOW, MEDIUM, or HIGH risk categories depending on the severity and number of triggered indicators.

The project also includes:

Behaviour tracking through persistent logging (log.txt)
Adaptive warning functionality based on repeated exposure to high-risk URLs
Dataset evaluation using 100 labelled URLs (50 legitimate and 50 phishing samples)
Accuracy, precision, and recall evaluation metrics
Detailed terminal scan reports showing triggered phishing indicators and scoring explanations

Key Features:

Rule-based phishing URL detection
Configurable JSON detection engine
URL parsing and structural analysis
Risk scoring and classification system
Behaviour tracking and adaptive warnings
Dataset evaluation and performance metrics
Modular and extensible Python architecture

Technologies Used:

Python
urllib.parse
JSON
pathlib
datetime

Project Results:

Accuracy: 98%
Precision: 100%
Recall: 96%

This project demonstrates how lightweight rule-based cybersecurity systems can provide effective phishing detection while maintaining transparency, explainability, and user awareness.
