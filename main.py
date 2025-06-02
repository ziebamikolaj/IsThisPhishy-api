from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, cast
from urllib.parse import urlparse
import dns.resolver
from datetime import datetime, timezone
import ssl
import socket
import whois # Import dla WHOIS

from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers.tokenization_utils_base import PreTrainedTokenizerBase
from transformers.modeling_utils import PreTrainedModel

import torch
from fastapi.middleware.cors import CORSMiddleware

# --- Konfiguracja CORS ---
app = FastAPI()
origins = [
    "http://localhost:5173",    # Twój frontend Vite
    "http://127.0.0.1:8000",    # Adres, na którym działa Uvicorn
    "chrome-extension://YOUR_EXTENSION_ID", # Zastąp rzeczywistym ID wtyczki Chrome
    "moz-extension://YOUR_EXTENSION_UUID"    # Zastąp rzeczywistym UUID wtyczki Firefox
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

class DomainDetailsResponse(BaseModel):
    domain_name: Optional[str] = None
    parsed_url_scheme: Optional[str] = None
    parsed_url_path: Optional[str] = None
    parsed_url_query: Optional[str] = None
    dns_records: Optional[Dict[str, List[str]]] = None
    ssl_info: Optional[SSLInfo] = None
    whois_info: Optional[WhoisInfo] = None
    domain_actual_age_days: Optional[int] = None
    is_ip_address_in_url: bool = False
    error: Optional[str] = None


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
        print(f"Error formatting RDN sequence: {e}, sequence was: {rdn_sequence}")
        return None

def get_ssl_certificate_info(hostname: str, port: int = 443) -> Optional[SSLInfo]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
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
        print(f"SSL check error for {hostname}: {type(e).__name__} - {e}")
        return None
    except Exception as e:
        print(f"Unexpected SSL check error for {hostname}: {type(e).__name__} - {e}")
        return None

@app.post("/api/v1/analyze_domain_details", response_model=DomainDetailsResponse)
async def analyze_domain_details_endpoint(request: DomainAnalysisRequest):
    try:
        parsed_url = urlparse(request.url)
        effective_url = request.url
        if not parsed_url.scheme and not parsed_url.netloc and '.' in request.url:
            effective_url = f"http://{request.url}" 
            parsed_url = urlparse(effective_url)
        
        domain_name_from_url = parsed_url.netloc
        if not domain_name_from_url:
            raise HTTPException(status_code=400, detail="Could not extract a valid domain/hostname from the URL.")

        is_ip_in_url = False
        hostname_for_ssl_and_dns = domain_name_from_url.split(':')[0] 
        try:
            socket.inet_aton(hostname_for_ssl_and_dns)
            is_ip_in_url = True
        except socket.error: pass

        domain_for_whois_query = hostname_for_ssl_and_dns
        if hostname_for_ssl_and_dns.startswith("www."):
            parts = hostname_for_ssl_and_dns.split('.', 1)
            if len(parts) > 1:
                domain_for_whois_query = parts[1]
        
        parts_for_whois = domain_for_whois_query.split('.')
        if len(parts_for_whois) > 2:
            if parts_for_whois[-2].lower() in ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'nom', 'me', 'ltd'] and len(parts_for_whois) > 2 : # dodano popularne drugie poziomy
                domain_for_whois_query = '.'.join(parts_for_whois[-3:])
            else:
                domain_for_whois_query = '.'.join(parts_for_whois[-2:])
        
        response_details = DomainDetailsResponse(
            domain_name=domain_name_from_url,
            parsed_url_scheme=parsed_url.scheme,
            parsed_url_path=parsed_url.path,
            parsed_url_query=parsed_url.query,
            is_ip_address_in_url=is_ip_in_url
        )

        # 1. Analiza DNS
        dns_results: Dict[str, List[str]] = {}
        if not is_ip_in_url and hostname_for_ssl_and_dns:
            fqdn_record_types = ['A', 'AAAA', 'CNAME']
            apex_fallback_record_types = ['MX', 'NS', 'TXT']

            for record_type in fqdn_record_types:
                try:
                    if not hostname_for_ssl_and_dns: continue
                    print(f"Attempting DNS lookup (FQDN) for: {hostname_for_ssl_and_dns} [{record_type}]")
                    answers = dns.resolver.resolve(hostname_for_ssl_and_dns, record_type)
                    dns_results[record_type] = [str(rdata) for rdata in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.YXDOMAIN) as e:
                    print(f"DNS lookup (FQDN) for {hostname_for_ssl_and_dns} [{record_type}] failed as expected: {type(e).__name__} - {e}")
                    dns_results[record_type] = [] 
                except Exception as e:
                    print(f"Unexpected DNS error (FQDN) for {hostname_for_ssl_and_dns} [{record_type}]: {type(e).__name__} - {e}")
                    dns_results[record_type] = [f"Error: {str(e)}"]

            for record_type in apex_fallback_record_types:
                resolved_values: Optional[List[str]] = None
                # Najpierw spróbuj FQDN
                try:
                    if not hostname_for_ssl_and_dns: 
                        dns_results[record_type] = [] # Jeśli nie ma FQDN, nie ma co próbować
                        continue
                    print(f"Attempting DNS lookup (FQDN) for: {hostname_for_ssl_and_dns} [{record_type}]")
                    answers = dns.resolver.resolve(hostname_for_ssl_and_dns, record_type)
                    resolved_values = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    # Używamy domain_for_whois_query jako naszej najlepszej próby dla "domeny głównej"
                    # Upewnij się, że domain_for_whois_query jest sensowne i różne od hostname_for_ssl_and_dns
                    if domain_for_whois_query and domain_for_whois_query != hostname_for_ssl_and_dns:
                        print(f"DNS lookup (FQDN) for {hostname_for_ssl_and_dns} [{record_type}] gave NoAnswer. Trying apex domain: {domain_for_whois_query}")
                        try:
                            answers_apex = dns.resolver.resolve(domain_for_whois_query, record_type)
                            resolved_values = [str(rdata) for rdata in answers_apex]
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.YXDOMAIN) as e_apex:
                            print(f"DNS lookup (Apex) for {domain_for_whois_query} [{record_type}] failed as expected: {type(e_apex).__name__} - {e_apex}")
                            resolved_values = [] # Zdefiniuj jako puste, jeśli błąd
                        except Exception as e_apex_other:
                            print(f"Unexpected DNS error (Apex) for {domain_for_whois_query} [{record_type}]: {type(e_apex_other).__name__} - {e_apex_other}")
                            resolved_values = [f"Error: {str(e_apex_other)}"]
                    else: 
                        resolved_values = [] # Zdefiniuj jako puste, jeśli nie ma co próbować dalej
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.YXDOMAIN) as e_fqdn:
                    print(f"DNS lookup (FQDN) for {hostname_for_ssl_and_dns} [{record_type}] failed as expected: {type(e_fqdn).__name__} - {e_fqdn}")
                    resolved_values = [] # Zdefiniuj jako puste
                except Exception as e_fqdn_other:
                    print(f"Unexpected DNS error (FQDN) for {hostname_for_ssl_and_dns} [{record_type}]: {type(e_fqdn_other).__name__} - {e_fqdn_other}")
                    resolved_values = [f"Error: {str(e_fqdn_other)}"]
                
                dns_results[record_type] = resolved_values if resolved_values is not None else []
            
            response_details.dns_records = dns_results

        # 2. Analiza certyfikatu SSL - użyj hostname_for_ssl_and_dns
        if (parsed_url.scheme == 'https' or (not parsed_url.scheme and not is_ip_in_url)) and hostname_for_ssl_and_dns:
            ssl_info_val = get_ssl_certificate_info(hostname_for_ssl_and_dns)
            response_details.ssl_info = ssl_info_val
        
        # 3. Analiza WHOIS - użyj domain_for_whois_query
        whois_data_obj = None
        domain_age = None
        if not is_ip_in_url and domain_for_whois_query:
            try:
                print(f"Attempting WHOIS lookup for: {domain_for_whois_query}")
                domain_whois_info = whois.whois(domain_for_whois_query)

                if domain_whois_info and (domain_whois_info.domain_name or domain_whois_info.get('domain_name')):
                    
                    def normalize_date_list(date_val: Any) -> Optional[datetime]:
                        if isinstance(date_val, list):
                            return date_val[0] if date_val and isinstance(date_val[0], datetime) else None
                        elif isinstance(date_val, datetime):
                            return date_val
                        return None

                    creation_dt = normalize_date_list(getattr(domain_whois_info, 'creation_date', domain_whois_info.get('creation_date')))
                    expiration_dt = normalize_date_list(getattr(domain_whois_info, 'expiration_date', domain_whois_info.get('expiration_date')))
                    updated_dt = normalize_date_list(getattr(domain_whois_info, 'updated_date', domain_whois_info.get('updated_date')))
                    
                    ns_list = getattr(domain_whois_info, 'name_servers', domain_whois_info.get('name_servers'))
                    emails_list = getattr(domain_whois_info, 'emails', domain_whois_info.get('emails'))
                    status_list = getattr(domain_whois_info, 'status', domain_whois_info.get('status'))
                    registrar_val = getattr(domain_whois_info, 'registrar', domain_whois_info.get('registrar'))

                    whois_data_obj = WhoisInfo(
                        registrar=str(registrar_val) if registrar_val else None,
                        creation_date=creation_dt,
                        expiration_date=expiration_dt,
                        updated_date=updated_dt,
                        name_servers=[str(ns).lower() for ns in ns_list] if isinstance(ns_list, list) else ([str(ns_list).lower()] if ns_list else None),
                        emails=[str(em).lower() for em in emails_list] if isinstance(emails_list, list) else ([str(emails_list).lower()] if emails_list else None),
                        status=[str(st) for st in status_list] if isinstance(status_list, list) else ([str(status_list)] if status_list else None)
                    )
                    
                    if creation_dt:
                        now_dt = datetime.now(timezone.utc) if creation_dt.tzinfo else datetime.now()
                        domain_age = (now_dt - creation_dt).days
                        
            except whois.parser.PywhoisError as e:
                print(f"WHOIS lookup for {domain_for_whois_query} resulted in PywhoisError: {e}")
            except Exception as e:
                print(f"WHOIS lookup for {domain_for_whois_query} failed: {type(e).__name__} - {e}")
        
        response_details.whois_info = whois_data_obj
        response_details.domain_actual_age_days = domain_age
        
        return response_details

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in analyze_domain_details_endpoint: {type(e).__name__} - {e}")
        return DomainDetailsResponse(error=f"An unexpected error occurred: {str(e)}")

# Uruchomienie: uvicorn main:app --reload