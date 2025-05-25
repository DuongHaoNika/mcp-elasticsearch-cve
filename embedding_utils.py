import os
import json
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions

class ExampleRetriever:
    def __init__(self, example_file=r"D:\Code\Python\AI\ES\example.json"):
        # Lấy đường dẫn tuyệt đối cho chroma_db
        chroma_db_path = os.path.abspath("./chroma_db")

        self.client = chromadb.PersistentClient(path=chroma_db_path)
        

        self.embedding_function = embedding_functions.DefaultEmbeddingFunction()
        
        self.collection = self.client.get_or_create_collection(
            name="cve_collection",
            metadata={"hnsw:space": "cosine"},
            embedding_function=self.embedding_function
        )
        
        with open(example_file, 'r', encoding='utf-8') as f:
            self.examples = json.load(f)
            
        # Thêm dữ liệu vào collection nếu chưa có
        if self.collection.count() == 0:
            self._add_examples()
            
    def _add_examples(self):
        """Thêm các ví dụ vào ChromaDB"""
        questions = [ex['question'] for ex in self.examples]
        answers = [json.dumps(ex['answer']) for ex in self.examples]
        ids = [f"example_{i}" for i in range(len(self.examples))]
        
        self.collection.add(
            documents=questions,
            metadatas=[{"answer": ans} for ans in answers],
            ids=ids
        )
        
    def get_similar_examples(self, query, k=3):
        results = self.collection.query(
            query_texts=[query],
            n_results=k
        )
        
        similar_examples = []
        for i in range(len(results['documents'][0])):
            # Chuyển đổi distance thành float64
            similarity = float(results['distances'][0][i])
            similar_examples.append({
                'question': results['documents'][0][i],
                'answer': json.loads(results['metadatas'][0][i]['answer']),
                'similarity': similarity
            })
            
        return similar_examples

def format_examples_for_prompt(examples):
    """Định dạng các ví dụ để đưa vào prompt"""
    formatted = "Example:\n"
    for i, ex in enumerate(examples, 1):
        formatted += f"Example {i}:\n"
        formatted += f"Question: {ex['question']}\n"
        formatted += f"Answer: {json.dumps(ex['answer'], indent=2)}\n\n"
    return formatted

def get_relevant_examples(query):
    """Hàm chính để lấy và hiển thị các ví dụ liên quan"""
    retriever = ExampleRetriever()
    similar_examples = retriever.get_similar_examples(query)
    
    # In ra terminal để debug
    print("\nRelavant examples:")
    print("-" * 50)
    for i, ex in enumerate(similar_examples, 1):
        # Chuyển đổi similarity thành float64 và tính độ tương đồng
        similarity_score = float(1 - ex['similarity'])
        print(f"\nExample: {i} (Similarity: {similarity_score:.4f}):")
        print(f"Question: {ex['question']}")
        print(f"Answer: {json.dumps(ex['answer'], indent=2)}")
    print("-" * 50)
    
    # Trả về định dạng cho prompt
    return format_examples_for_prompt(similar_examples)

if __name__ == "__main__":
    test_queries = [
        "Show 3 CVE about XSS in 2024",
        "Show 3 CVE about SQL injection in WordPress",
        "Show 3 CVE have highest CVSS Score"
    ]
    
    for query in test_queries:
        print(f"\n\nTest with question: {query}")
        get_relevant_examples(query) 