"""
Retriever for Threat Intelligence RAG Engine.
Queries ChromaDB to find relevant threat data based on user queries.
"""

from typing import List, Dict, Any
from app.ai.threat_rag.embedding_engine import embedding_engine

class Retriever:
    def __init__(self):
        self.engine = embedding_engine

    def retrieve(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        collection = self.engine.get_collection()
        if not collection:
            return []

        try:
            results = collection.query(
                query_texts=[query],
                n_results=top_k
            )
            
            retrieved_docs = []
            if results and results['documents'] and results['documents'][0]:
                for doc_idx, doc_content in enumerate(results['documents'][0]):
                    metadata = results['metadatas'][0][doc_idx] if results['metadatas'] else {}
                    retrieved_docs.append({
                        "content": doc_content,
                        "metadata": metadata
                    })
            return retrieved_docs
        except Exception as e:
            return []

# Singleton instance
retriever = Retriever()
