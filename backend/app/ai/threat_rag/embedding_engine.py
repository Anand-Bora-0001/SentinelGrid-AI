"""
Embedding Engine for Threat Intelligence RAG.
Manages ChromaDB vector store initialization and document population.
"""

import logging
from typing import Optional
from app.ai.threat_rag.document_loader import load_all_documents

logger = logging.getLogger(__name__)

class SimpleLocalEmbeddingFunction:
    def __call__(self, input: list[str]) -> list[list[float]]:
        embeddings = []
        for text in input:
            vector = [0.0] * 384
            words = text.lower().split()
            for word in words:
                idx = sum(ord(c) for c in word) % 384
                vector[idx] += 1.0
            norm = sum(x**2 for x in vector)**0.5
            if norm > 0:
                vector = [x / norm for x in vector]
            embeddings.append(vector)
        return embeddings

    def embed_query(self, input: list[str]) -> list[list[float]]:
        return self.__call__(input)

    @staticmethod
    def name() -> str:
        return "SimpleLocalEmbeddingFunction"

    def get_config(self) -> dict:
        return {}

    @staticmethod
    def build_from_config(config: dict) -> "SimpleLocalEmbeddingFunction":
        return SimpleLocalEmbeddingFunction()

class EmbeddingEngine:
    def __init__(self):
        self.collection = None
        self.chroma_available = False
        self._init_chroma()

    def _init_chroma(self):
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
            
            client = chromadb.Client(ChromaSettings(anonymized_telemetry=False))
            self.collection = client.get_or_create_collection(
                name="threat_intelligence_v2",
                metadata={"hnsw:space": "cosine"},
                embedding_function=SimpleLocalEmbeddingFunction()
            )
            
            if self.collection.count() == 0:
                self._populate()
            
            self.chroma_available = True
            logger.info("ChromaDB initialized for Threat Intelligence RAG Engine")
        except ImportError:
            logger.warning("ChromaDB or required modules not available")
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")

    def _populate(self):
        if not self.collection:
            return
            
        docs = load_all_documents()
        
        documents = []
        metadatas = []
        ids = []
        
        for idx, doc in enumerate(docs):
            content = f"{doc['id']}: {doc['name']} - {doc['description']}"
            documents.append(content)
            metadatas.append({
                "id": doc['id'],
                "name": doc['name'],
                "source": doc['source']
            })
            ids.append(f"doc_{idx}")
            
        if documents:
            self.collection.add(documents=documents, metadatas=metadatas, ids=ids)
            logger.info(f"Populated ChromaDB with {len(documents)} threat intelligence documents")

    def get_collection(self):
        return self.collection

# Singleton instance
embedding_engine = EmbeddingEngine()
