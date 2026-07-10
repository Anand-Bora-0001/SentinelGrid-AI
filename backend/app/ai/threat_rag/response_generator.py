"""
Response Generator for Threat Intelligence RAG Engine.
Generates structured answers based on user query and retrieved context.
"""

from typing import List, Dict, Any

class ResponseGenerator:
    def generate(self, question: str, retrieved_docs: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not retrieved_docs:
            return {
                "question": question,
                "answer": "I do not have enough information to answer that question.",
                "sources": []
            }

        # Simplified "generation" since we aren't using an LLM directly for text generation,
        # we'll extract the best explanation from the context.
        # In a real implementation with an LLM, this would pass context to the LLM prompt.
        
        best_doc = retrieved_docs[0]
        metadata = best_doc.get("metadata", {})
        
        # Build answer from context
        answer_parts = []
        for doc in retrieved_docs:
            content = doc.get("content", "")
            if content:
                # Add basic text parsing to make it look like a generated answer
                answer_parts.append(content)
        
        answer = "Based on our Threat Intelligence sources: " + ". ".join(answer_parts) + "."
        
        sources = list(set([doc.get("metadata", {}).get("source", "Unknown Source") for doc in retrieved_docs]))
        
        return {
            "question": question,
            "answer": answer,
            "sources": sources
        }

# Singleton instance
response_generator = ResponseGenerator()
