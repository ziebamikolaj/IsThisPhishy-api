# Anti-Phishing API

A high-performance, full-stack solution designed to identify and analyze phishing threats in real-time. This project was developed as the backend component for a Bachelor's Thesis in Computer Science, powering a Chrome browser extension that warns users about suspicious websites.

The API is built with **Python** and **FastAPI**, ensuring scalability and speed. It integrates multiple layers of analysis, from DNS and SSL checks to real-time blacklist lookups and AI-powered text classification.

---

## Features

This API provides two main endpoints for comprehensive threat analysis:

### 1. **AI-Powered Text Classification (`/api/v1/check_phishing_text`)**
-   **Description:** Analyzes a given block of text (like an email body or website content) to determine if it contains phishing-related language.
-   **Core Technology:** Leverages a pre-trained **BERT model** (`phishbot/ScamLLM`) via the `transformers` library for state-of-the-art sequence classification.
-   **Output:** Returns a boolean `is_phishing` flag, a `confidence` score, and a clear `label` ("LEGITIMATE" or "PHISHING").

### 2. **In-Depth URL/Domain Analysis (`/api/v1/analyze_domain_details`)**
-   **Description:** Performs a deep, multi-vector analysis of a given URL to gather intelligence and assess its risk profile.
-   **Key Analysis Vectors:**
    -   **DNS Records:** Fetches and returns major DNS records (A, AAAA, CNAME, MX, NS, TXT) for the domain.
    -   **SSL Certificate:** Verifies the SSL certificate, extracting issuer, subject, and validity dates.
    -   **WHOIS Data:** Retrieves domain registration information, including creation date, registrar, and name servers, to calculate domain age.
    -   **Real-time Blacklist Checks:** Cross-references the URL/domain/IP against multiple, aggregated threat intelligence feeds:
        -   Google Safe Browsing API
        -   OpenPhish
        -   PhishTank
        -   CERT.PL (Polish National CERT)
        -   Spamhaus DNSBL
    -   **Heuristics:** Detects common phishing patterns like the use of raw IP addresses in the URL.

---

## Architecture & Performance

The system is designed for both speed and accuracy, employing several key architectural patterns:

-   **Asynchronous by Design:** Built on **FastAPI**, the entire API is asynchronous, allowing for high-concurrency and non-blocking I/O during external lookups (DNS, WHOIS, APIs).
-   **Intelligent Caching:**
    -   **In-Memory TTL Cache:** Full domain analysis responses are cached in-memory (`cachetools.TTLCache`) to provide near-instantaneous results for repeated queries.
    -   **Threat Feed Caching:** Blacklist feeds (OpenPhish, PhishTank, CERT.PL) are fetched and cached locally on a timed basis, reducing latency and reliance on external services for every request.
-   **Robust URL Parsing:** Utilizes `tldextract` for precise extraction of the registered domain, ensuring that WHOIS and other domain-level checks are performed on the correct entity (e.g., `example.co.uk` instead of just `co.uk`).
-   **Efficient Data Models:** Leverages **Pydantic** for rigorous data validation, serialization, and clear API contract definition, ensuring data integrity throughout the system.

---

## Setup & Installation

To run this project locally, follow these steps:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ziebamikolaj/bachelor-thesis.git
    cd bachelor-thesis
    ```

2.  **Create a virtual environment and install dependencies:**
    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3.  **Set up environment variables:**
    Create a `.env` file in the root directory and add your Google Safe Browsing API key:
    ```
    GOOGLE_SAFE_BROWSING_API_KEY="YOUR_API_KEY_HERE"
    ```
    The application will automatically download the necessary AI model on first run.

4.  **Run the application:**
    ```bash
    uvicorn main:app --reload
    ```
    The API will be available at `http://127.0.0.1:8000`.

---

## Future Development

This project serves as a strong foundation for a more comprehensive threat intelligence platform. Potential future improvements include:
-   Integration with more threat intelligence feeds.
-   Adding screenshot analysis for visual detection of phishing kits.
-   Building a historical database to track the reputation of domains over time.
