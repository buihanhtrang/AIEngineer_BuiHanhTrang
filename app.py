import os
import json
import re
import time
import socket
import hashlib
from datetime import datetime
from urllib.parse import urlparse
import requests
from flask import Flask, request, jsonify
from openai import OpenAI

# Initialize Flask app
app = Flask(__name__)

# Configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', 'your-openai-api-key')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'your-virustotal-api-key')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'your-abuseipdb-api-key')

# Initialize OpenAI client
client = OpenAI(api_key=OPENAI_API_KEY)

class SecurityAnalysisAgent:
    def __init__(self):
        self.virustotal_base_url = "https://www.virustotal.com/api/v3"
        self.abuseipdb_base_url = "https://api.abuseipdb.com/api/v2"

    def analyze_url_virustotal(self, url):
        """Analyze URL using VirusTotal API"""
        try:
            headers = {
                'x-apikey': VIRUSTOTAL_API_KEY
            }

            # Submit URL for analysis
            data = {'url': url}
            response = requests.post(f"{self.virustotal_base_url}/urls",
                                     headers=headers,
                                     data=data,
                                     timeout=30
                                     )

            if response.status_code != 200:
                return {"error": "Failed to submit URL to VirusTotal"}
            # Get analysis ID
            analysis_id = response.json()['data']['id']
            # Wait a bit and get results
            time.sleep(2)
            analysis_response = requests.get(
                f"{self.virustotal_base_url}/analyses/{analysis_id}",
                headers=headers,
                timeout=30)

            if analysis_response.status_code == 200:
                result = analysis_response.json()
                stats = result['data']['attributes']['stats']
                return {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "clean": stats.get('clean', 0),
                    "timeout": stats.get('timeout', 0),
                    "total": sum(stats.values())
                }
            else:
                return {"error": "Failed to get analysis results"}

        except Exception as e:
            return {"error": f"VirusTotal API error: {str(e)}"}

    def analyze_hash_virustotal(self, file_hash):
        try:
            headers = {
                'x-apikey': VIRUSTOTAL_API_KEY
            }
            response = requests.get(
                f"{self.virustotal_base_url}/files/{file_hash}",
                headers=headers
            )
            if response.status_code == 200:
                data = response.json()['data']['attributes']['last_analysis_stats']
                return {
                    "malicious": data.get("malicious", 0),
                    "suspicious": data.get("suspicious", 0),
                    "harmless": data.get("harmless", 0),
                    "undetected": data.get("undetected", 0),
                    "timeout": data.get("timeout", 0),
                    "total": sum(data.values())
                }
            else:
                return {"error": f"VirusTotal Hash check failed: {response.status_code}"}
        except Exception as e:
            return {"error": f"Hash analysis error: {str(e)}"}


    def analyze_ip_abuseipdb(self, ip):
        """Analyze IP using AbuseIPDB API"""
        try:
            headers = {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }

            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }

            response = requests.get(
                f"{self.abuseipdb_base_url}/check",
                headers=headers,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                data = result['data']
                return {
                    "abuse_confidence": data.get('abuseConfidencePercentage', 0),
                    "is_public": data.get('isPublic', True),
                    "is_whitelisted": data.get('isWhitelisted', False),
                    "country_code": data.get('countryCode', 'Unknown'),
                    "total_reports": data.get('totalReports', 0)
                }
            else:
                return {"error": "Failed to check IP with AbuseIPDB"}

        except Exception as e:
            return {"error": f"AbuseIPDB API error: {str(e)}"}

    def analyze_domain_reputation(self, domain):
        """Basic domain reputation analysis"""
        try:
            # Check if domain resolves
            try:
                ip = socket.gethostbyname(domain)
                dns_resolves = True
            except:
                ip = None
                dns_resolves = False

            # Check for suspicious patterns
            suspicious_patterns = [
                r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}',  # IP-like patterns
                r'[a-z0-9]{20,}',  # Long random strings
                r'(bit\.ly|tinyurl|short)',  # URL shorteners
                r'[0-9]+[a-z]+[0-9]+',  # Mixed numbers and letters
            ]
            is_suspicious = any(re.search(pattern, domain, re.IGNORECASE)
                                for pattern in suspicious_patterns)

            return {
                "dns_resolves": dns_resolves,
                "resolved_ip": ip,
                "suspicious_pattern": is_suspicious,
                "domain_length": len(domain)
            }

        except Exception as e:
            return {"error": f"Domain analysis error: {str(e)}"}

    def analyze_file_path(self, file_path):
        """Analyze file path for suspicious characteristics"""
        try:
            # Common legitimate Windows paths
            legitimate_paths = [
                r'C:\\Windows\\System32\\',
                r'C:\\Windows\\SysWOW64\\',
                r'C:\\Program Files\\',
                r'C:\\Program Files (x86)\\',
            ]

            # Suspicious characteristics
            suspicious_indicators = {
                "temp_directory": any(temp in file_path.lower()
                                            for temp in ['temp', 'tmp', 'appdata\\local\\temp']),
                "unusual_location": not any(path.lower() in file_path.lower()
                                            for path in legitimate_paths),
                "double_extension": file_path.count('.') > 1,
                "hidden_chars": any(char in file_path
                                            for char in ['\\\\', '//']),
                "suspicious_name": any(sus in file_path.lower()
                                            for sus in ['svchost', 'winlogon', 'csrss'])
                                            and 'System32' not in file_path
            }

            risk_score = sum(suspicious_indicators.values())

            return {
                "file_path": file_path,
                "risk_score": risk_score,
                "indicators": suspicious_indicators,
                "is_system_path": any(path.lower() in file_path.lower()
                                      for path in legitimate_paths)
            }

        except Exception as e:
            return {"error": f"File analysis error: {str(e)}"}

    def get_gpt_analysis(self, query, tool_results):
        """Get GPT-4 analysis based on query and tool results"""
        try:
            system_prompt = """
            Bạn là một chuyên gia an toàn thông tin. Hãy phân tích các kết quả từ các công cụ bảo mật và đưa ra kết luận cuối cùng.

            Quy tắc phân loại:
            - ABNORMAL: Có dấu hiệu độc hại rõ ràng hoặc nghi ngờ cao
            - CLEAN: Không có dấu hiệu nguy hiểm, được xác nhận an toàn
            - UNKNOWN: Không đủ thông tin để xác định hoặc có dấu hiệu mơ hồ

            Hãy đưa ra phân tích chi tiết và kết luận cuối cùng.
            """

            user_prompt = f"""
            Truy vấn: {query}

            Kết quả từ các công cụ phân tích:
            {json.dumps(tool_results, indent=2, ensure_ascii=False)}

            Hãy phân tích và đưa ra kết luận theo format:
            - analysis: Phân tích chi tiết
            - result: ABNORMAL/CLEAN/UNKNOWN
            """

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3
            )

            return response.choices[0].message.content

        except Exception as e:
            return f"GPT Analysis error: {str(e)}"

    def detect_query_type(self, query):
        """Detect what type of security object the query is about"""
        query_lower = query.lower()

        # URL patterns
        if re.search(r'https?://', query) or re.search(r'www\.', query) or 'url' in query_lower:
            return 'url'

        # IP patterns
        if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', query):
            return 'ip'

        # Hash patterns (SHA-256)
        if re.search(r'\b[a-fA-F0-9]{64}\b', query):
            return 'hash'

        # File path patterns
        if re.search(r'[a-zA-Z]:\\', query) or re.search(r'\.exe|\.dll|\.bat|\.cmd', query):
            return 'file'

        # Domain patterns
        if re.search(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', query):
            return 'domain'

        return 'unknown'

    def analyze_query(self, query):
        """Main analysis function"""
        query_type = self.detect_query_type(query)
        tool_results = {}

        # Extract the actual target from query
        target = self.extract_target(query)

        if query_type == 'url':
            tool_results['virustotal'] = self.analyze_url_virustotal(target)
            domain = urlparse(target).netloc
            tool_results['domain_reputation'] = self.analyze_domain_reputation(domain)

        elif query_type == 'ip':
            tool_results['abuseipdb'] = self.analyze_ip_abuseipdb(target)

        elif query_type == 'hash':
            file_hash = self.extract_target(query)
            tool_results['hash_analysis'] = self.analyze_hash_virustotal(file_hash)

        elif query_type == 'file':
            tool_results['file_analysis'] = self.analyze_file_path(target)

        elif query_type == 'domain':
            tool_results['domain_reputation'] = self.analyze_domain_reputation(target)
            tool_results['virustotal'] = self.analyze_url_virustotal(f"http://{target}")

        else:
            tool_results['error'] = 'Unable to determine query type'

        # Get GPT analysis
        gpt_result = self.get_gpt_analysis(query, tool_results)

        # Parse GPT result to extract analysis and result
        try:
            # Simple parsing - in production, you might want more robust parsing
            lines = gpt_result.split('\n')
            analysis = ""
            result = "UNKNOWN"

            for line in lines:
                if 'analysis:' in line.lower() or 'phân tích:' in line.lower():
                    analysis = line.split(':', 1)[1].strip()
                elif 'result:' in line.lower() or 'kết luận:' in line.lower():
                    result_line = line.split(':', 1)[1].strip()
                    if 'ABNORMAL' in result_line.upper():
                        result = 'ABNORMAL'
                    elif 'CLEAN' in result_line.upper():
                        result = 'CLEAN'
                    else:
                        result = 'UNKNOWN'

            if not analysis:
                analysis = gpt_result

        except:
            analysis = gpt_result
            result = "UNKNOWN"

        return {
            "analysis": analysis,
            "result": result,
            "tool_results": tool_results,
            "query_type": query_type
        }

    def extract_target(self, query):
        """Extract the actual target (URL, IP, file, domain) from query"""
        # URL pattern
        url_match = re.search(r'https?://[^\s]+', query)
        if url_match:
            return url_match.group(0)

        # IP pattern
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', query)
        if ip_match:
            return ip_match.group(0)

        # Hash pattern (SHA-256)
        hash_match = re.search(r'\b[a-fA-F0-9]{64}\b', query)
        if hash_match:
            return hash_match.group(0)

        # File path pattern
        file_match = re.search(r'[a-zA-Z]:\\[^\s]+', query)
        if file_match:
            return file_match.group(0)

        # Domain pattern
        domain_match = re.search(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', query)
        if domain_match:
            return domain_match.group(0)

        return query.strip()

# Initialize agent
agent = SecurityAnalysisAgent()

@app.route('/analysis_agent', methods=['POST'])
def analysis_agent():
    try:
        data = request.get_json()

        if not data or 'query' not in data:
            return jsonify({"error": "Missing 'query' parameter"}), 400

        query = data['query']
        result = agent.analyze_query(query)

        # Return only analysis and result as specified
        return jsonify({
            "analysis": result['analysis'],
            "result": result['result']
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8989, debug=True)
