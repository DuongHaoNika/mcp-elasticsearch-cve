import chainlit as cl
from main import search_cves
import httpx
import json
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Config
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2"

def is_valid_value(value):
    """Kiểm tra giá trị có hợp lệ không"""
    if value is None:
        return False
    if isinstance(value, str):
        value = value.lower().strip()
        return value and value != 'n/a' and value != 'none' and value != 'unknown'
    return True

async def get_requested_count(user_question: str) -> int:
    # Thử tìm số trực tiếp từ câu hỏi trước
    numbers = re.findall(r'\b\d+\b', user_question)
    if numbers:
        logger.info(f"Found number directly in question: {numbers[0]}")
        return int(numbers[0])
        
    prompt = f"""
Bạn là một trợ lý phân tích câu hỏi. Nhiệm vụ của bạn là TRẢ VỀ MỘT SỐ DUY NHẤT.

Câu hỏi: {user_question}

Hãy trả về:
- Số lượng CVE mà người dùng muốn xem
- Nếu không có số lượng cụ thể, trả về 5
- CHỈ TRẢ VỀ MỘT SỐ, KHÔNG CÓ BẤT KỲ KÝ TỰ NÀO KHÁC

Ví dụ:
- "Liệt kê 10 CVE về XSS" -> 10
- "Show 3 CVE about SQL injection" -> 3
- "Tìm CVE về buffer overflow" -> 5
"""
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(OLLAMA_URL, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        llama_response = data.get("response", "5").strip()
        logger.info(f"Llama response: {llama_response}")
        
        # Tìm số trong phản hồi
        numbers = re.findall(r'\b\d+\b', llama_response)
        if numbers:
            count = int(numbers[0])
            logger.info(f"Parsed count from Llama: {count}")
            return count
            
        logger.warning("No number found in Llama response, using default 5")
        return 5

@cl.on_chat_start
async def start():
    await cl.Message(
        content="Xin chào! Tôi là trợ lý tìm kiếm CVE. Bạn có thể hỏi tôi về các lỗ hổng bảo mật bằng tiếng Việt hoặc tiếng Anh."
    ).send()

@cl.on_message
async def main(message: cl.Message):
    # Hiển thị thông báo đang xử lý
    msg = cl.Message(content="Đang tìm kiếm thông tin...")
    await msg.send()
    
    # Lấy số lượng CVE cần hiển thị
    requested_count = await get_requested_count(message.content)
    logger.info(f"Requested count for question '{message.content}': {requested_count}")
    
    # Gọi hàm search_cves từ main.py
    result = search_cves(message.content)

    print(result)
    
    if "error" in result:
        await cl.Message(
            content=f"Có lỗi xảy ra: {result['error']}"
        ).send()
        return
    
    if result['total'] == 0:
        await cl.Message(
            content="Không tìm thấy kết quả nào phù hợp với câu hỏi của bạn."
        ).send()
        return
        
    # Tạo response message
    response = f"Tìm thấy {result['total']} kết quả. Hiển thị {min(requested_count, len(result['results']))} kết quả phù hợp nhất:\n\n"
    
    # Hiển thị kết quả
    cnt = 0
    for cve in result['results'][:requested_count]:
        cnt += 1
        response += f"**{cnt}. {cve['cve_id']}**\n"
        
        if is_valid_value(cve.get('title')):
            response += f"Tiêu đề: {cve['title']}\n"
            
        if is_valid_value(cve.get('date_published')):
            response += f"Ngày công bố: {cve['date_published']}\n"
        
        # Thêm thông tin về vendor và sản phẩm bị ảnh hưởng
        if cve.get('affected'):
            has_valid_info = False
            affected_info = []
            
            for affected in cve['affected']:
                vendor = affected.get('vendor')
                product = affected.get('product')
                versions = affected.get('versions', [])
                
                if is_valid_value(vendor) or is_valid_value(product) or versions:
                    has_valid_info = True
                    info = []
                    if is_valid_value(vendor):
                        info.append(f"Vendor: {vendor}")
                    if is_valid_value(product):
                        info.append(f"Sản phẩm: {product}")
                    if versions:
                        version_info = []
                        for version in versions:
                            version_str = version.get('version')
                            status = version.get('status')
                            less_than = version.get('lessThan')
                            
                            if is_valid_value(less_than):
                                version_str = f"< {less_than}"
                            elif not is_valid_value(version_str):
                                continue
                                
                            if is_valid_value(status):
                                version_str += f" ({status})"
                            version_info.append(version_str)
                        
                        if version_info:
                            info.append("Phiên bản bị ảnh hưởng: " + ", ".join(version_info))
                    
                    if info:
                        affected_info.append("- " + "\n- ".join(info))
            
            if has_valid_info:
                response += "Sản phẩm bị ảnh hưởng:\n" + "\n".join(affected_info) + "\n"
        
        if is_valid_value(cve.get('description')):
            response += f"Mô tả: {cve['description']}\n"
        
        # Thêm thông tin về CVSS nếu có
        if cve.get('metrics'):
            for metric in cve['metrics']:
                if 'cvssV3_1' in metric:
                    cvss = metric['cvssV3_1']
                    base_score = cvss.get('baseScore')
                    severity = cvss.get('baseSeverity')
                    vector = cvss.get('vectorString')
                    
                    if is_valid_value(base_score):
                        response += "CVSS Score:\n"
                        response += f"- Base Score: {base_score}"
                        if is_valid_value(severity):
                            response += f" ({severity})"
                        response += "\n"
                        
                        # Thêm thông tin chi tiết về CVSS
                        attack_vector = cvss.get('attackVector')
                        attack_complexity = cvss.get('attackComplexity')
                        privileges_required = cvss.get('privilegesRequired')
                        user_interaction = cvss.get('userInteraction')
                        scope = cvss.get('scope')
                        confidentiality_impact = cvss.get('confidentialityImpact')
                        integrity_impact = cvss.get('integrityImpact')
                        availability_impact = cvss.get('availabilityImpact')
                        
                        if any(is_valid_value(x) for x in [attack_vector, attack_complexity, privileges_required, 
                                                         user_interaction, scope, confidentiality_impact, 
                                                         integrity_impact, availability_impact]):
                            response += "- Chi tiết:\n"
                            if is_valid_value(attack_vector):
                                response += f"  + Attack Vector: {attack_vector}\n"
                            if is_valid_value(attack_complexity):
                                response += f"  + Attack Complexity: {attack_complexity}\n"
                            if is_valid_value(privileges_required):
                                response += f"  + Privileges Required: {privileges_required}\n"
                            if is_valid_value(user_interaction):
                                response += f"  + User Interaction: {user_interaction}\n"
                            if is_valid_value(scope):
                                response += f"  + Scope: {scope}\n"
                            if is_valid_value(confidentiality_impact):
                                response += f"  + Confidentiality Impact: {confidentiality_impact}\n"
                            if is_valid_value(integrity_impact):
                                response += f"  + Integrity Impact: {integrity_impact}\n"
                            if is_valid_value(availability_impact):
                                response += f"  + Availability Impact: {availability_impact}\n"
                        
                        if is_valid_value(vector):
                            response += f"- Vector: {vector}\n"
        
        if cve.get('urls'):
            valid_urls = [url for url in cve['urls'] if is_valid_value(url)]
            if valid_urls:
                response += "URLs:\n"
                for url in valid_urls:
                    response += f"- {url}\n"
        response += "\n"
    
    await cl.Message(content=response).send()