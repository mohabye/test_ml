import time
import threading
import json
import logging
from src.traffic_analyzer import TrafficAnalyzer

class WAFCore:
    def __init__(self, model_path, config=None):
        self.analyzer = TrafficAnalyzer(model_path)
        self.config = config or {}
        self.enabled = True
        self.block_mode = self.config.get('block_mode', True)
        self.log_file = self.config.get('log_file', 'logs/waf.log')
        self.setup_logging()
        
        self.whitelist = set(self.config.get('ip_whitelist', []))
        self.blacklist = set(self.config.get('ip_blacklist', []))
        
        self.rate_limits = {}
        self.rate_limit_threshold = self.config.get('rate_limit_threshold', 100)
        self.rate_limit_window = self.config.get('rate_limit_window', 60)
        
        self.lock = threading.Lock()
    
    def setup_logging(self):
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('waf')
    
    def process_request(self, request):
        if not self.enabled:
            return {'allowed': True, 'reason': 'WAF disabled'}
        
        client_ip = request.get('client_ip', '0.0.0.0')
        
        if client_ip in self.whitelist:
            return {'allowed': True, 'reason': 'IP whitelisted'}
        
        if client_ip in self.blacklist:
            self.log_blocked_request(request, 'IP blacklisted')
            return {'allowed': False, 'reason': 'IP blacklisted'}
        
        if self.is_rate_limited(client_ip):
            self.log_blocked_request(request, 'Rate limited')
            return {'allowed': False, 'reason': 'Rate limited'}
        
        is_attack = self.analyzer.analyze_request(request)
        
        if is_attack:
            attack_type = request.get('attack_type', 'unknown')
            reason = f'Attack detected: {attack_type}'
            
            if self.block_mode:
                self.log_blocked_request(request, reason)
                return {'allowed': False, 'reason': reason}
            else:
                self.logger.warning(f"Attack detected but not blocked (monitor mode): {json.dumps(request)}")
                return {'allowed': True, 'reason': 'Monitor mode enabled'}
        
        return {'allowed': True, 'reason': 'No threat detected'}
    
    def is_rate_limited(self, client_ip):
        current_time = time.time()
        
        with self.lock:
            if client_ip not in self.rate_limits:
                self.rate_limits[client_ip] = {'count': 1, 'window_start': current_time}
                return False
            
            rate_data = self.rate_limits[client_ip]
            
            if current_time - rate_data['window_start'] > self.rate_limit_window:
                self.rate_limits[client_ip] = {'count': 1, 'window_start': current_time}
                return False
            
            rate_data['count'] += 1
            
            if rate_data['count'] > self.rate_limit_threshold:
                return True
            
            return False
    
    def log_blocked_request(self, request, reason):
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'client_ip': request.get('client_ip', '0.0.0.0'),
            'method': request.get('method', ''),
            'url': request.get('url', ''),
            'reason': reason
        }
        
        self.logger.warning(f"Blocked request: {json.dumps(log_entry)}")
    
    def toggle_enabled(self):
        self.enabled = not self.enabled
        status = "enabled" if self.enabled else "disabled"
        self.logger.info(f"WAF {status}")
        return self.enabled
    
    def toggle_block_mode(self):
        self.block_mode = not self.block_mode
        mode = "block" if self.block_mode else "monitor"
        self.logger.info(f"WAF mode changed to: {mode}")
        return self.block_mode
    
    def add_to_whitelist(self, ip):
        self.whitelist.add(ip)
        self.logger.info(f"Added IP to whitelist: {ip}")
    
    def add_to_blacklist(self, ip):
        self.blacklist.add(ip)
        self.logger.info(f"Added IP to blacklist: {ip}")
    
    def get_stats(self):
        return self.analyzer.get_stats()
    
    def get_recent_attacks(self, limit=10):
        return self.analyzer.get_recent_attacks(limit)
