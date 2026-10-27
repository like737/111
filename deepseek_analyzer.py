"""
DeepSeek API 分析模块 - 调用DeepSeek大模型分析URL安全性
"""

import json
import requests
from typing import Dict, Optional

class DeepSeekAnalyzer:
    """调用DeepSeek API进行URL安全分析"""

    API_URL = "https://api.deepseek.com/v1/chat/completions"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    def analyze(self, url: str) -> Optional[Dict]:
        """
        使用DeepSeek分析URL安全性
        
        Args:
            url: 待检测的URL
            
        Returns:
            Dict包含:
                - is_malicious: bool
                - score: int (0-100, 越低越危险)
                - risk_level: str
                - reasons: List[str]
                或 {"error": "错误信息"}
        """
        if not self.api_key:
            return {"error": "未配置DeepSeek API密钥"}

        prompt = f"""你是一个专业的网络安全URL检测专家。请分析以下URL是否为恶意链接，并给出评分和理由。

URL: {url}

请严格按以下JSON格式回复（不要包含其他任何内容）：
{{
    "is_malicious": true或false,
    "score": 0-100的整数,
    "risk_level": "安全"或"可疑"或"危险",
    "reasons": ["原因1", "原因2"]
}}

评分规则：0=黑名单，1-69=危险，70-99=安全，100=白名单。
"""

        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "你是一个网络安全专家，擅长分析URL的安全性。"},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1,
                "max_tokens": 800
            }

            response = requests.post(
                self.API_URL,
                headers=headers,
                json=payload,
                timeout=30
            )
            response.raise_for_status()

            result = response.json()
            content = result["choices"][0]["message"]["content"]

            # 清理可能的 markdown 代码块标记
            content = content.strip()
            if "```json" in content:
                content = content.split("```json")[1]
            if "```" in content:
                content = content.split("```")[0]
            content = content.strip()

            analysis = json.loads(content)
            return {
                "is_malicious": analysis.get("is_malicious", False),
                "score": max(0, min(100, int(analysis.get("score", 50)))),
                "risk_level": analysis.get("risk_level", "未知"),
                "reasons": analysis.get("reasons", []),
                "source": "DeepSeek AI"
            }

        except Exception as e:
            return {"error": f"DeepSeek API调用失败: {str(e)}"}