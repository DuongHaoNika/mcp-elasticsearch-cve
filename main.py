from typing import Any
from fastmcp import FastMCP
from elasticsearch import Elasticsearch
import json
import socket
import threading
import logging
import httpx

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Config
OLLAMA_URL = "http://localhost:11434/api/generate"  # Ollama API endpoint
OLLAMA_MODEL = "llama3.2"  # Model name
INDEX = "cvesearch"  # Elasticsearch index name

# Initialize FastMCP server
mcp = FastMCP("elasticsearch-ollama-cves")

# Initialize Elasticsearch client
es = Elasticsearch(
    ["http://localhost:9200"]
)

def llama_generate_query(user_question: str) -> dict:
    prompt = f"""
Bạn là một trợ lý an ninh mạng. Dưới đây là ví dụ về một bản ghi CVE trong Elasticsearch:
<JSON>
{{
    "cveMetadata": {{
        "cveId": "CVE-2025-1944",
        "state": "PUBLISHED",
        "datePublished": "2025-01-28T18:27:32.084Z"
    }},
    "containers": {{
        "cna": {{
            "affected": [{{"product": "picklescan", "vendor": "mmaitre314"}}],
            "descriptions": [{{"lang": "en", "value": "picklescan before 0.0.23 is vulnerable to a ZIP archive manipulation attack..."}}],
            "title": "picklescan ZIP archive manipulation attack leads to crash"
        }}
    }}
}}
</JSON>

Nhiệm vụ của bạn là: Chỉ sinh ra Elasticsearch Query DSL (dạng JSON) để tìm kiếm các bản ghi mà trường "containers.cna.descriptions.value" chứa thông tin liên quan đến chủ đề người dùng hỏi. Nếu người dùng hỏi về số lượng (ví dụ: 'liệt kê 10 CVE', 'top 5 CVE', 'show 3 CVE'), hãy thêm trường "size": <số lượng> vào query. Nếu người dùng đề cập đến thời gian (ví dụ năm 2025), hãy thêm điều kiện lọc theo trường "cveMetadata.datePublished" để chỉ lấy các CVE được công bố trong năm 2025. Không sinh query cho trường khác. Không giải thích gì thêm, chỉ trả về JSON query.

Ví dụ:
Nếu người dùng hỏi: "Liệt kê 10 CVE về XSS trong năm 2025"
Thì bạn trả về:
{{
  "size": 10,
  "query": {{
    "bool": {{
      "must": [
        {{
          "match": {{
            "containers.cna.descriptions.value": "XSS"
          }}
        }},
        {{
          "range": {{
            "cveMetadata.datePublished": {{
              "gte": "2025-01-01T00:00:00Z",
              "lte": "2025-12-31T23:59:59Z"
            }}
          }}
        }}
      ]
    }}
  }}
}}

Nếu người dùng hỏi: "Show 3 CVE about SQL injection"
Thì bạn trả về:
{{
  "size": 3,
  "query": {{
    "match": {{
      "containers.cna.descriptions.value": "SQL injection"
    }}
  }}
}}

Ví dụ:
Nếu người dùng hỏi: "Liệt kê 10 CVE về XSS từ tháng 1 đến tháng 3 năm 2025"
Thì bạn trả về:
{{
  "size": 10,
  "query": {{
    "bool": {{
      "must": [
        {{
          "match": {{
            "containers.cna.descriptions.value": "XSS"
          }}
        }},
        {{
          "range": {{
            "cveMetadata.datePublished": {{
              "gte": "2025-01-01T00:00:00Z",
              "lte": "2025-03-31T23:59:59Z"
            }}
          }}
        }}
      ]
    }}
  }}
}}

Nếu người dùng không nói rõ số lượng, không cần thêm trường "size".

Chỉ trả về JSON query đúng chuẩn Elasticsearch, không thêm bất kỳ giải thích nào.

Câu hỏi: {user_question}
"""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }
    response = httpx.post(OLLAMA_URL, json=payload, timeout=60)
    response.raise_for_status()
    data = response.json()
    import json as pyjson
    try:
        query = pyjson.loads(data.get("response", ""))
    except Exception:
        import re
        match = re.search(r'({[\s\S]+})', data.get("response", ""))
        if match:
            query = pyjson.loads(match.group(1))
        else:
            raise ValueError("Không thể parse query từ Llama")
    return query

@mcp.tool()
def search_cves(user_question: str) -> dict:
    """
    Nhận câu hỏi tự nhiên, dùng Llama sinh query, sau đó tìm kiếm trên Elasticsearch.
    Trả về thông tin ngắn gọn về các CVE.
    """
    try:
        query = llama_generate_query(user_question)
        result = es.search(index=INDEX, body=query)
        
        # Tạo response ngắn gọn
        simplified_results = []
        for hit in result.get('hits', {}).get('hits', []):
            source = hit.get('_source', {})
            cna = source.get('containers', {}).get('cna', {})
            
            # Lấy danh sách URL từ references
            urls = []
            for ref in cna.get('references', []):
                if 'url' in ref:
                    urls.append(ref['url'])
            
            simplified_cve = {
                'cve_id': source.get('cveMetadata', {}).get('cveId', ''),
                'title': cna.get('title', ''),
                'description': cna.get('descriptions', [{}])[0].get('value', '') if cna.get('descriptions') else '',
                'score': hit.get('_score', 0),
                'date_published': source.get('cveMetadata', {}).get('datePublished', ''),
                'urls': urls
            }
            simplified_results.append(simplified_cve)
            
        return {
            'total': result.get('hits', {}).get('total', {}).get('value', 0),
            'results': simplified_results
        }
    except Exception as e:
        return {"error": str(e)}

class MCPServer:
    def __init__(self, config_file='config.json'):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
            
        self.host = self.config['mcp_server']['host']
        self.port = self.config['mcp_server']['port']
        es_host = self.config['elasticsearch']['host']
        es_port = self.config['elasticsearch']['port']
        self.index = self.config['elasticsearch']['index']
        
        self.es = Elasticsearch([f'http://{es_host}:{es_port}'])
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            logger.info(f"MCP Server started on {self.host}:{self.port}")
            
            while True:
                client_socket, address = self.server_socket.accept()
                logger.info(f"New connection from {address}")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()
                
        except Exception as e:
            logger.error(f"Server error: {str(e)}")
            self.server_socket.close()
            
    def handle_client(self, client_socket):
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                    
                request = json.loads(data.decode('utf-8'))
                response = self.process_request(request)
                client_socket.send(json.dumps(response).encode('utf-8'))
                
        except Exception as e:
            logger.error(f"Error handling client: {str(e)}")
        finally:
            client_socket.close()
            
    def process_request(self, request):
        try:
            action = request.get('action')
            if action == 'search':
                query = request.get('query', {})
                result = self.es.search(index=self.index, body=query)
                return {'status': 'success', 'data': result}
            else:
                return {'status': 'error', 'message': 'Invalid action'}
                
        except Exception as e:
            logger.error(f"Error processing request: {str(e)}")
            return {'status': 'error', 'message': str(e)}

if __name__ == "__main__":
    mcp.run()
