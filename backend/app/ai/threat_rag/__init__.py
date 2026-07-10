"""
Threat Intelligence RAG Engine
"""

from typing import Dict, Any
from app.ai.threat_rag.retriever import retriever
from app.ai.threat_rag.response_generator import response_generator

class ThreatRAGEngine:
    @property
    def db_available(self) -> bool:
        from app.ai.threat_rag.embedding_engine import embedding_engine
        return embedding_engine.chroma_available

    def ask(self, question: str) -> Dict[str, Any]:
        """
        Main entrypoint for asking the Threat Intelligence Engine.
        """
        # Retrieve context
        retrieved_docs = retriever.retrieve(question, top_k=2)
        
        # Generate response
        response = response_generator.generate(question, retrieved_docs)
        
        return response

    def query(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Query threat intelligence context based on telemetry event fields.
        """
        parts = []
        if event_dict.get("mitre_technique_id"):
            parts.append(event_dict["mitre_technique_id"])
        if event_dict.get("event_type"):
            parts.append(event_dict["event_type"])
        if event_dict.get("action"):
            parts.append(event_dict["action"])
        if event_dict.get("command"):
            parts.append(event_dict["command"])
            
        question = " ".join(parts).strip()
        if not question:
            question = "security advisory"
            
        return self.ask(question)

# Global instances
threat_rag_engine = ThreatRAGEngine()
threat_rag = threat_rag_engine
