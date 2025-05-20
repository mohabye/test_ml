import pickle
import pandas as pd
import numpy as np
import json
import time
import os
import re
from datetime import datetime
from src.feature_engineering import extract_request_features

class TrafficAnalyzer:
    def __init__(self, model_path):
        self.model = self.load_model(model_path)
        self.request_buffer = []
        self.detection_stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'attack_types': {
                'sql_injection': 0,
                'xss': 0,
                'path_traversal': 0,
                'other': 0
            }
        }
        self.snort_alert_file = "/var/snort/alert"
        self.snort_log_file_pattern = "/var/snort/snort.log.*"
        self.last_alert_size = 0
        self.last_alert_check = 0
    
    def load_model(self, model_path):
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        return model
    
    def classify_attack_type(self, request):
        if 'url' not in request or 'payload' not in request:
            return 'other'
        
        url = request['url'].lower()
        payload = request['payload'].lower()
        
        if any(keyword in payload for keyword in ['select', 'union', 'insert', 'update', 'delete', 'drop', '--', '/*', '*/']):
            return 'sql_injection'
        elif any(keyword in payload for keyword in ['<script', 'javascript:', 'onerror', 'onload', 'eval(', 'document.cookie']):
            return 'xss'
        elif any(keyword in url or keyword in payload for keyword in ['../', '../', '..\\', 'etc/passwd', 'etc/shadow']):
            return 'path_traversal'
        else:
            return 'other'
    
    def parse_snort_alert(self, alert_text):
        """Parse Snort alert text into a structured format"""
        request = {}
        
        # Extract rule ID and description
        rule_match = re.search(r'\[\*\*\] \[(\d+:\d+:\d+)\] (.*?) \[\*\*\]', alert_text)
        if rule_match:
            request['rule_id'] = rule_match.group(1)
            request['alert_msg'] = rule_match.group(2)
        
        # Extract classification and priority
        class_match = re.search(r'\[Classification: (.*?)\] \[Priority: (\d+)\]', alert_text)
        if class_match:
            request['classification'] = class_match.group(1)
            request['priority'] = int(class_match.group(2))
        
        # Extract timestamp, source and destination IPs
        ip_match = re.search(r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+) ([\d\.]+) -> ([\d\.]+)', alert_text)
        if ip_match:
            request['timestamp'] = ip_match.group(1)
            request['client_ip'] = ip_match.group(2)
            request['server_ip'] = ip_match.group(3)
        
        # Extract protocol information
        proto_match = re.search(r'(TCP|UDP|ICMP|HTTP) TTL:(\d+)', alert_text)
        if proto_match:
            request['protocol'] = proto_match.group(1)
            request['ttl'] = int(proto_match.group(2))
        
        # Construct URL and payload from available information
        if 'client_ip' in request and 'server_ip' in request:
            request['url'] = f"http://{request['server_ip']}"
            
        # Extract payload from packet dump if available
        payload_match = re.search(r'ORIGINAL DATAGRAM DUMP:(.*?)END OF DUMP', alert_text, re.DOTALL)
        if payload_match:
            request['payload'] = payload_match.group(1).strip()
        else:
            request['payload'] = alert_text  # Use the whole alert as payload for feature extraction
        
        # Set method based on protocol
        if 'protocol' in request:
            if request['protocol'] == 'HTTP':
                request['method'] = 'GET'  # Assume GET by default for HTTP
            else:
                request['method'] = request['protocol']
        
        return request
    
    def check_snort_alerts(self):
        """Check for new Snort alerts and process them"""
        current_time = time.time()
        
        # Only check for new alerts every 5 seconds
        if current_time - self.last_alert_check < 5:
            return []
        
        self.last_alert_check = current_time
        new_requests = []
        
        try:
            # Check if alert file exists and has been modified
            if not os.path.exists(self.snort_alert_file):
                return []
            
            current_size = os.path.getsize(self.snort_alert_file)
            if current_size <= self.last_alert_size:
                return []
            
            # Read new alerts
            with open(self.snort_alert_file, 'r') as f:
                f.seek(self.last_alert_size)
                alert_data = f.read()
            
            self.last_alert_size = current_size
            
            # Split alerts by blank lines
            alerts = re.split(r'\n\s*\n', alert_data)
            
            for alert in alerts:
                if not alert.strip():
                    continue
                
                request = self.parse_snort_alert(alert)
                if request:
                    new_requests.append(request)
        
        except Exception as e:
            print(f"Error reading Snort alerts: {e}")
        
        return new_requests
    
    def analyze_request(self, request):
        self.detection_stats['total_requests'] += 1
        
        features = extract_request_features(request)
        features_df = pd.DataFrame([features])
        
        prediction = self.model.predict(features_df)[0]
        
        if prediction == 1:
            self.detection_stats['blocked_requests'] += 1
            attack_type = self.classify_attack_type(request)
            self.detection_stats['attack_types'][attack_type] += 1
            
            request['is_attack'] = True
            request['attack_type'] = attack_type
            request['timestamp'] = time.time()
            
            self.request_buffer.append(request)
            if len(self.request_buffer) > 100:
                self.request_buffer.pop(0)
            
            return True
        else:
            request['is_attack'] = False
            return False
    
    def process_snort_data(self):
        """Process new Snort alerts and analyze them"""
        new_requests = self.check_snort_alerts()
        results = []
        
        for request in new_requests:
            is_attack = self.analyze_request(request)
            results.append({
                'request': request,
                'is_attack': is_attack,
                'attack_type': request.get('attack_type', 'unknown') if is_attack else None
            })
        
        return results
    
    def get_recent_attacks(self, limit=10):
        return sorted(
            [req for req in self.request_buffer if req.get('is_attack', False)],
            key=lambda x: x.get('timestamp', 0),
            reverse=True
        )[:limit]
    
    def get_stats(self):
        return self.detection_stats
    
    def reset_stats(self):
        self.detection_stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'attack_types': {
                'sql_injection': 0,
                'xss': 0,
                'path_traversal': 0,
                'other': 0
            }
        }
