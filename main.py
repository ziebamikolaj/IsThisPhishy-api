import os
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, cast
from urllib.parse import urlparse
import dns.resolver
from datetime import datetime, timezone
import ssl
import socket
import whois
import tldextract # Dla precyzyjnego wyodrębniania domeny

from dotenv import load_dotenv
load_dotenv() # Załaduj zmienne z .env, jeśli istnieje

from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers.tokenization_utils_base import PreTrainedTokenizerBase
from transformers.modeling_utils import PreTrainedModel

import torch
from fastapi.middleware.cors import CORSMiddleware

from cachetools import TTLCache, Cache
import json # Do serializacji/deserializacji obiektów Pydantic dla cache'u

# --- Konfiguracja kluczy API i URL-i ---
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "YOUR_GOOGLE_KEY_HERE_IF_NOT_IN_ENV")
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

# --- Konfiguracja CORS ---
app = FastAPI()
origins = [
    "http://localhost:5173",    # Twój frontend Vite
    "http://127.0.0.1:8000",    # Adres, na którym działa Uvicorn
    "chrome-extension://YOUR_CHROME_EXTENSION_ID_HERE", # Zastąp rzeczywistym ID wtyczki Chrome
    "moz-extension://YOUR_FIREFOX_EXTENSION_UUID_HERE"    # Zastąp rzeczywistym UUID wtyczki Firefox
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Ładowanie modelu i tokenizera ---
MODEL_NAME = "ealvaradob/bert-finetuned-phishing"
tokenizer_instance: Optional[PreTrainedTokenizerBase] = None
model_instance: Optional[PreTrainedModel] = None

try:
    tokenizer_instance = AutoTokenizer.from_pretrained(MODEL_NAME)
    _temp_model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    if isinstance(_temp_model, PreTrainedModel):
        model_instance = _temp_model
        model_instance.eval()
        print(f"Model {MODEL_NAME} loaded successfully.")
    else:
        print(f"Error: Model loaded is not an instance of PreTrainedModel.")
        model_instance = None
except Exception as e:
    print(f"Error loading model: {e}")
    tokenizer_instance = None
    model_instance = None

# --- Konfiguracja Cache'u ---
DOMAIN_ANALYSIS_CACHE: TTLCache[str, str] = TTLCache(maxsize=1024, ttl=3600)


# --- Modele danych Pydantic ---
class PhishingCheckRequest(BaseModel):
    text_to_analyze: str

class PhishingCheckResponse(BaseModel):
    is_phishing: bool
    confidence: float
    label: str

class DomainAnalysisRequest(BaseModel):
    url: str = Field(..., examples=["https://www.example.com/path?query=value"])

class SSLInfo(BaseModel):
    issuer: Optional[Dict[str, str]] = None
    subject: Optional[Dict[str, str]] = None
    version: Optional[int] = None
    serial_number: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None

class WhoisInfo(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    name_servers: Optional[List[str]] = None
    emails: Optional[List[str]] = None
    status: Optional[List[str]] = None

class BlacklistCheckResult(BaseModel):
    source: str
    is_listed: bool
    details: Optional[Any] = None

class DomainDetailsResponse(BaseModel):
    domain_name: Optional[str] = None
    parsed_url_scheme: Optional[str] = None
    parsed_url_path: Optional[str] = None
    parsed_url_query: Optional[str] = None
    dns_records: Optional[Dict[str, List[str]]] = None
    ssl_info: Optional[SSLInfo] = None
    whois_info: Optional[WhoisInfo] = None
    domain_actual_age_days: Optional[int] = None
    blacklist_checks: Optional[List[BlacklistCheckResult]] = None
    is_ip_address_in_url: bool = False
    error: Optional[str] = None


# --- Funkcje pomocnicze do sprawdzania list zagrożeń ---
OPENPHISH_LOCAL_CACHE: List[str] = []
OPENPHISH_CACHE_TIMESTAMP: Optional[datetime] = None
OPENPHISH_CACHE_TTL_SECONDS = 3600

def update_openphish_cache():
    global OPENPHISH_LOCAL_CACHE, OPENPHISH_CACHE_TIMESTAMP
    now = datetime.now(timezone.utc)
    if OPENPHISH_CACHE_TIMESTAMP is None or (now - OPENPHISH_CACHE_TIMESTAMP).total_seconds() > OPENPHISH_CACHE_TTL_SECONDS:
        try:
            print(f"Attempting to update OpenPhish cache from {OPENPHISH_FEED_URL}...")
            headers = {'User-Agent': 'IsThisPhishyApp/1.0 (compatible; Python Requests)'}
            response = requests.get(OPENPHISH_FEED_URL, timeout=30, headers=headers)
            response.raise_for_status()
            new_entries = [line.strip() for line in response.text.splitlines() if line.strip()]
            if new_entries:
                OPENPHISH_LOCAL_CACHE = new_entries
                OPENPHISH_CACHE_TIMESTAMP = now
                print(f"OpenPhish cache updated successfully with {len(OPENPHISH_LOCAL_CACHE)} entries.")
            else:
                print("OpenPhish feed was empty. Cache not updated.")
        except requests.exceptions.Timeout:
            print(f"Timeout while updating OpenPhish cache from {OPENPHISH_FEED_URL}.")
        except requests.exceptions.RequestException as e:
            print(f"Error updating OpenPhish cache: {e}")

def check_openphish(url_to_check: str) -> BlacklistCheckResult:
    update_openphish_cache()
    is_listed = url_to_check in OPENPHISH_LOCAL_CACHE
    if is_listed:
        print(f"URL '{url_to_check}' found in OpenPhish cache.")
    return BlacklistCheckResult(source="OpenPhish", is_listed=is_listed, details={"match_found": is_listed, "cache_size": len(OPENPHISH_LOCAL_CACHE)})

def check_google_safe_browsing(url_to_check: str) -> BlacklistCheckResult:
    if not GOOGLE_SAFE_BROWSING_API_KEY or GOOGLE_SAFE_BROWSING_API_KEY.startswith("YOUR_"):
        return BlacklistCheckResult(source="GoogleSafeBrowsing", is_listed=False, details="API key not configured")
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "isthisphishy-app", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        is_listed = 'matches' in data and len(data['matches']) > 0
        return BlacklistCheckResult(source="GoogleSafeBrowsing", is_listed=is_listed, details=data.get('matches'))
    except requests.RequestException as e:
        print(f"Error checking Google Safe Browsing for {url_to_check}: {e}")
        return BlacklistCheckResult(source="GoogleSafeBrowsing", is_listed=False, details=f"API request error: {e}")
    except ValueError as e: # JSONDecodeError
        print(f"Error decoding Google Safe Browsing JSON for {url_to_check}: {e}")
        return BlacklistCheckResult(source="GoogleSafeBrowsing", is_listed=False, details=f"JSON decode error: {e}")

def check_ip_dnsbl(ip_address: str, dnsbl_server: str = "zen.spamhaus.org") -> BlacklistCheckResult:
    try:
        reversed_ip = '.'.join(reversed(ip_address.split('.')))
        query_domain = f"{reversed_ip}.{dnsbl_server}"
        # print(f"Checking IP {ip_address} against DNSBL {dnsbl_server} (querying {query_domain})") # Zakomentowane dla czystszych logów
        answers = dns.resolver.resolve(query_domain, 'A')
        return BlacklistCheckResult(source=dnsbl_server, is_listed=True, details=[str(rdata) for rdata in answers])
    except dns.resolver.NXDOMAIN:
        return BlacklistCheckResult(source=dnsbl_server, is_listed=False)
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        # print(f"DNSBL lookup error for IP {ip_address} on {dnsbl_server}: {e}") # Zakomentowane
        return BlacklistCheckResult(source=dnsbl_server, is_listed=False, details=f"DNSBL lookup error: {e}")
    except Exception as e:
        # print(f"Unexpected error during DNSBL check for IP {ip_address} on {dnsbl_server}: {e}") # Zakomentowane
        return BlacklistCheckResult(source=dnsbl_server, is_listed=False, details=f"Unexpected error: {e}")

# --- Endpointy API ---
@app.post("/api/v1/check_phishing_text", response_model=PhishingCheckResponse)
async def check_phishing_text(request: PhishingCheckRequest):
    if not tokenizer_instance or not model_instance:
        raise HTTPException(status_code=503, detail="Phishing detection model is not available.")
    try:
        inputs = tokenizer_instance(request.text_to_analyze, return_tensors="pt", truncation=True, padding=True, max_length=512) # type: ignore[operator]
        with torch.no_grad():
            outputs = model_instance(**inputs) # type: ignore[operator]
            logits = outputs.logits
        
        probabilities = torch.softmax(logits, dim=1).squeeze()
        predicted_class_id = torch.argmax(probabilities).item()
        confidence_value = probabilities[predicted_class_id].item() # type: ignore[index]

        label_map_val = None
        if hasattr(model_instance, 'config') and model_instance.config and hasattr(model_instance.config, 'id2label'):
            label_map_val = model_instance.config.id2label
        
        if label_map_val:
            predicted_label = label_map_val[predicted_class_id]
        else:
            print("Warning: Model config or id2label not found. Using default labels.")
            predicted_label = "PHISHING" if predicted_class_id == 1 else "LEGITIMATE"

        is_phishing_pred = (predicted_label.lower() == "phishing")
        return PhishingCheckResponse(
            is_phishing=is_phishing_pred,
            confidence=confidence_value,
            label=predicted_label.upper()
        )
    except Exception as e:
        print(f"Error during phishing prediction: {type(e).__name__} - {e}")
        raise HTTPException(status_code=500, detail=f"Error during text analysis: {str(e)}")

def format_rdn(rdn_sequence: Any) -> Optional[Dict[str, str]]:
    if not rdn_sequence: return None
    try:
        formatted_dict: Dict[str, str] = {}
        for rdn_set in rdn_sequence:
            for rdn in rdn_set:
                if isinstance(rdn, tuple) and len(rdn) == 2 and isinstance(rdn[0], str) and isinstance(rdn[1], str):
                    formatted_dict[rdn[0]] = rdn[1]
        return formatted_dict if formatted_dict else None
    except Exception as e:
        # print(f"Error formatting RDN sequence: {e}, sequence was: {rdn_sequence}") # Zakomentowane
        return None

def get_ssl_certificate_info(hostname: str, port: int = 443) -> Optional[SSLInfo]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock: 
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert: Optional[Dict[str, Any]] = ssock.getpeercert()
                if not cert: return None
                issuer_dict = format_rdn(cert.get('issuer'))
                subject_dict = format_rdn(cert.get('subject'))
                version_val = cert.get('version')
                serial_val = cert.get('serialNumber')
                not_before_str = cert.get('notBefore')
                not_after_str = cert.get('notAfter')
                ssl_version: Optional[int] = version_val if isinstance(version_val, int) else None
                ssl_serial_number: Optional[str] = serial_val if isinstance(serial_val, str) else None
                ssl_not_before: Optional[datetime] = None
                if isinstance(not_before_str, str):
                    try: ssl_not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                    except ValueError: pass
                ssl_not_after: Optional[datetime] = None
                if isinstance(not_after_str, str):
                    try: ssl_not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    except ValueError: pass
                return SSLInfo(issuer=issuer_dict, subject=subject_dict, version=ssl_version,
                               serial_number=ssl_serial_number, not_before=ssl_not_before, not_after=ssl_not_after)
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError, ValueError) as e:
        # print(f"SSL check error for {hostname}: {type(e).__name__} - {e}") # Zakomentowane
        return None
    except Exception as e:
        # print(f"Unexpected SSL check error for {hostname}: {type(e).__name__} - {e}") # Zakomentowane
        return None

def pydantic_encoder(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

@app.post("/api/v1/analyze_domain_details", response_model=DomainDetailsResponse)
async def analyze_domain_details_endpoint(request: DomainAnalysisRequest):
    cache_key = request.url
    cached_response_json = DOMAIN_ANALYSIS_CACHE.get(cache_key)
    if cached_response_json:
        print(f"Cache hit for: {cache_key}")
        try:
            cached_data = json.loads(cached_response_json)
            return DomainDetailsResponse(**cached_data)
        except (json.JSONDecodeError, TypeError, Exception) as e: # TypeError dla Pydantic ValidationError
            print(f"Error decoding/validating cached JSON for {cache_key}: {e}. Fetching fresh data.")
            DOMAIN_ANALYSIS_CACHE.pop(cache_key, None)

    print(f"Cache miss for: {cache_key}. Fetching fresh data.")
    domain_name_from_url: Optional[str] = None 
    try:
        parsed_url = urlparse(request.url)
        effective_url_for_parsing = request.url
        if not parsed_url.scheme and not parsed_url.netloc and '.' in request.url:
            effective_url_for_parsing = f"http://{request.url}"
            parsed_url = urlparse(effective_url_for_parsing)
        
        domain_name_from_url = parsed_url.netloc
        if not domain_name_from_url:
            raise HTTPException(status_code=400, detail="Could not extract a valid domain/hostname from the URL.")

        is_ip_in_url = False
        hostname_for_ops = domain_name_from_url.split(':')[0]
        try:
            socket.inet_aton(hostname_for_ops)
            is_ip_in_url = True
        except socket.error: pass

        extracted_domain_parts = tldextract.extract(hostname_for_ops)
        domain_for_whois_query = ""
        if extracted_domain_parts.registered_domain:
            domain_for_whois_query = extracted_domain_parts.registered_domain
        else:
            domain_for_whois_query = hostname_for_ops 
        
        print(f"URL received: {request.url}")
        print(f"Hostname for DNS/SSL: {hostname_for_ops}, Domain for WHOIS/ApexDNS: {domain_for_whois_query}")

        response_details = DomainDetailsResponse(
            domain_name=domain_name_from_url,
            parsed_url_scheme=parsed_url.scheme,
            parsed_url_path=parsed_url.path,
            parsed_url_query=parsed_url.query,
            is_ip_address_in_url=is_ip_in_url
        )

        # --- DNS ---
        dns_records_val: Dict[str, List[str]] = {}
        if not is_ip_in_url and hostname_for_ops:
            apex_domain_for_dns = domain_for_whois_query 
            fqdn_record_types = ['A', 'AAAA', 'CNAME']
            apex_fallback_record_types = ['MX', 'NS', 'TXT']
            all_dns_types = fqdn_record_types + apex_fallback_record_types
            for record_type in all_dns_types:
                current_host_to_query = hostname_for_ops
                resolved_values: Optional[List[str]] = None
                try:
                    # print(f"Attempting DNS lookup for: {current_host_to_query} [{record_type}]")
                    answers = dns.resolver.resolve(current_host_to_query, record_type)
                    resolved_values = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    if record_type in apex_fallback_record_types and apex_domain_for_dns and apex_domain_for_dns != current_host_to_query:
                        # print(f"DNS NoAnswer for {current_host_to_query} [{record_type}]. Trying apex: {apex_domain_for_dns}")
                        try:
                            answers_apex = dns.resolver.resolve(apex_domain_for_dns, record_type)
                            resolved_values = [str(rdata) for rdata in answers_apex]
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.YXDOMAIN): resolved_values = []
                        except Exception: resolved_values = ["Error: Apex DNS lookup failed"]
                    else: resolved_values = []
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.YXDOMAIN): resolved_values = []
                except Exception: resolved_values = [f"Error: DNS lookup for {record_type} failed"]
                dns_records_val[record_type] = resolved_values if resolved_values is not None else []
            response_details.dns_records = dns_records_val

        # --- SSL ---
        if (parsed_url.scheme == 'https' or (not parsed_url.scheme and not is_ip_in_url)) and hostname_for_ops:
            response_details.ssl_info = get_ssl_certificate_info(hostname_for_ops)
        
        # --- WHOIS ---
        whois_info_val = None
        domain_age_val = None
        if not is_ip_in_url and domain_for_whois_query:
            try:
                # print(f"Attempting WHOIS lookup for: {domain_for_whois_query}")
                domain_whois_info = whois.whois(domain_for_whois_query)
                if domain_whois_info and (getattr(domain_whois_info, 'domain_name', None) or domain_whois_info.get('domain_name')):
                    def normalize_date_list(date_val: Any) -> Optional[datetime]:
                        if isinstance(date_val, list): return date_val[0] if date_val and isinstance(date_val[0], datetime) else None
                        elif isinstance(date_val, datetime): return date_val
                        return None
                    creation_dt = normalize_date_list(getattr(domain_whois_info, 'creation_date', domain_whois_info.get('creation_date')))
                    expiration_dt = normalize_date_list(getattr(domain_whois_info, 'expiration_date', domain_whois_info.get('expiration_date')))
                    updated_dt = normalize_date_list(getattr(domain_whois_info, 'updated_date', domain_whois_info.get('updated_date')))
                    ns_list = getattr(domain_whois_info, 'name_servers', domain_whois_info.get('name_servers'))
                    emails_list = getattr(domain_whois_info, 'emails', domain_whois_info.get('emails'))
                    status_list = getattr(domain_whois_info, 'status', domain_whois_info.get('status'))
                    registrar_val = getattr(domain_whois_info, 'registrar', domain_whois_info.get('registrar'))
                    whois_info_val = WhoisInfo(
                        registrar=str(registrar_val) if registrar_val else None, creation_date=creation_dt, expiration_date=expiration_dt, updated_date=updated_dt,
                        name_servers=[str(ns).lower() for ns in ns_list] if isinstance(ns_list, list) else ([str(ns_list).lower()] if ns_list else None),
                        emails=[str(em).lower() for em in emails_list] if isinstance(emails_list, list) else ([str(emails_list).lower()] if emails_list else None),
                        status=[str(st) for st in status_list] if isinstance(status_list, list) else ([str(status_list)] if status_list else None)
                    )
                    if creation_dt:
                        now_dt = datetime.now(timezone.utc) if creation_dt.tzinfo else datetime.now()
                        domain_age_val = (now_dt - creation_dt).days
            except whois.parser.PywhoisError as e_whois_parse: print(f"WHOIS parse error for {domain_for_whois_query}: {e_whois_parse}")
            except Exception as e_whois: print(f"WHOIS error for {domain_for_whois_query}: {type(e_whois).__name__} - {e_whois}")
        response_details.whois_info = whois_info_val
        response_details.domain_actual_age_days = domain_age_val

        # --- Sprawdzanie list zagrożeń ---
        all_blacklist_checks: List[BlacklistCheckResult] = []
        url_to_check_on_blacklists = request.url 
        all_blacklist_checks.append(check_openphish(url_to_check_on_blacklists))
        all_blacklist_checks.append(check_google_safe_browsing(url_to_check_on_blacklists))
        if response_details.dns_records and 'A' in response_details.dns_records:
            unique_ips_to_check = set()
            for ip_addr in response_details.dns_records['A']:
                if ip_addr and not ip_addr.startswith("Error:") and ip_addr not in unique_ips_to_check:
                    all_blacklist_checks.append(check_ip_dnsbl(ip_addr))
                    unique_ips_to_check.add(ip_addr)
        response_details.blacklist_checks = all_blacklist_checks
        
        try:
            # Sprawdź wersję Pydantic lub po prostu spróbuj obu metod
            try:
                response_as_dict = response_details.model_dump(exclude_none=True, by_alias=True) # Pydantic v2+
            except AttributeError:
                response_as_dict = response_details.dict(exclude_none=True, by_alias=True) # Pydantic v1
            
            DOMAIN_ANALYSIS_CACHE[cache_key] = json.dumps(response_as_dict, default=pydantic_encoder)
            print(f"Saved to cache: {cache_key}")
        except Exception as e_cache_save: 
            print(f"Error saving to cache for {cache_key}: {e_cache_save}")
        
        return response_details

    except HTTPException: 
        raise
    except Exception as e:
        print(f"Critical error in analyze_domain_details_endpoint: {type(e).__name__} - {e}")
        error_domain_name = domain_name_from_url if domain_name_from_url else request.url
        # Zwróć błąd w strukturze DomainDetailsResponse, aby klient nadal mógł go sparsować
        # Nie cache'uj błędów krytycznych, aby umożliwić ponowną próbę
        return DomainDetailsResponse(
            domain_name=error_domain_name,
            error=f"An critical unexpected error occurred: {str(e)}"
        )

# Uruchomienie: uvicorn main:app --reload