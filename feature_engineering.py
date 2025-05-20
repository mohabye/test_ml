import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse, parse_qs

def extract_url_features(url):
    features = {}
    
    parsed_url = urlparse(url)
    
    features['url_length'] = len(url)
    features['path_length'] = len(parsed_url.path)
    features['query_length'] = len(parsed_url.query)
    
    features['path_token_count'] = len(parsed_url.path.split('/'))
    features['path_avg_token_length'] = np.mean([len(token) for token in parsed_url.path.split('/') if token]) if parsed_url.path else 0
    
    query_params = parse_qs(parsed_url.query)
    features['query_param_count'] = len(query_params)
    
    features['contains_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['contains_script_tag'] = 1 if re.search(r'<script.*?>|<\/script>', url, re.IGNORECASE) else 0
    features['contains_sql_keywords'] = 1 if re.search(r'union\s+select|select\s+from|insert\s+into|update\s+set|delete\s+from', url, re.IGNORECASE) else 0
    
    return features

def extract_payload_features(payload):
    features = {}
    
    features['payload_length'] = len(payload)
    features['special_char_count'] = sum(c in '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\' for c in payload)
    features['digit_count'] = sum(c.isdigit() for c in payload)
    features['uppercase_count'] = sum(c.isupper() for c in payload)
    
    features['contains_script_tag'] = 1 if re.search(r'<script.*?>|<\/script>', payload, re.IGNORECASE) else 0
    features['contains_iframe'] = 1 if re.search(r'<iframe.*?>|<\/iframe>', payload, re.IGNORECASE) else 0
    features['contains_event_handler'] = 1 if re.search(r'on\w+\s*=', payload, re.IGNORECASE) else 0
    features['contains_sql_keywords'] = 1 if re.search(r'union\s+select|select\s+from|insert\s+into|update\s+set|delete\s+from', payload, re.IGNORECASE) else 0
    features['contains_file_inclusion'] = 1 if re.search(r'\.\.\/|\.\.\\', payload) else 0
    
    return features

def extract_request_features(request_data):
    features = {}
    
    features.update(extract_url_features(request_data.get('url', '')))
    
    if 'payload' in request_data:
        payload_features = extract_payload_features(request_data['payload'])
        features.update({f'payload_{k}': v for k, v in payload_features.items()})
    
    features['method_is_get'] = 1 if request_data.get('method', '').upper() == 'GET' else 0
    features['method_is_post'] = 1 if request_data.get('method', '').upper() == 'POST' else 0
    features['has_user_agent'] = 1 if 'user_agent' in request_data and request_data['user_agent'] else 0
    
    return features

def process_batch(requests_batch):
    features_list = []
    
    for request in requests_batch:
        features = extract_request_features(request)
        features_list.append(features)
    
    return pd.DataFrame(features_list)

def main():
    sample_request = {
        'url': 'http://example.com/login.php?user=admin&password=pass123',
        'method': 'POST',
        'payload': "username=admin' OR '1'='1&password=anything",
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    features = extract_request_features(sample_request)
    print("Extracted features:")
    for key, value in features.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    main()
