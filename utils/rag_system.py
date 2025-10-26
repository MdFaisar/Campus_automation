import os
import logging
from datetime import datetime
from typing import List, Dict, Any
import json
import PyPDF2
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
from groq import Groq
from .firebase_config import get_firestore_client
from .file_manager import FileManager

logger = logging.getLogger(__name__)

class RAGSystem:
    def __init__(self):
        self.file_manager = FileManager()
        """Initialize RAG system with embeddings and vector store"""
        self.groq_client = Groq(api_key=os.environ.get('GROQ_API_KEY'))
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.vector_store = None
        self.documents = []
        self.document_chunks = []
        self.db = get_firestore_client()
        self.index_file = "vector_index.faiss"
        self.docs_file = "documents.json"
        
        # Initialize or load existing vector store
        self._load_or_create_vector_store()
    
    def _load_or_create_vector_store(self):
        """Load existing vector store or create new one"""
        try:
            if os.path.exists(self.index_file) and os.path.exists(self.docs_file):
                # Load existing index
                self.vector_store = faiss.read_index(self.index_file)
                with open(self.docs_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.documents = data.get('documents', [])
                    self.document_chunks = data.get('chunks', [])
                logger.info("Loaded existing vector store")
            else:
                # Create new index
                self.vector_store = faiss.IndexFlatIP(384)  # 384 is the dimension for all-MiniLM-L6-v2
                self.documents = []
                self.document_chunks = []
                logger.info("Created new vector store")
        except Exception as e:
            logger.error(f"Error loading vector store: {str(e)}")
            # Fallback to new index
            self.vector_store = faiss.IndexFlatIP(384)
            self.documents = []
            self.document_chunks = []
    
    def _save_vector_store(self):
        """Save vector store to disk"""
        try:
            faiss.write_index(self.vector_store, self.index_file)
            with open(self.docs_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'documents': self.documents,
                    'chunks': self.document_chunks
                }, f, ensure_ascii=False, indent=2, default=str)
            logger.info("Vector store saved successfully")
        except Exception as e:
            logger.error(f"Error saving vector store: {str(e)}")
    
    def _extract_text_from_pdf(self, file_path: str) -> str:
        """Extract text from PDF file"""
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                text = ""
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
            return text.strip()
        except Exception as e:
            logger.error(f"Error extracting text from PDF: {str(e)}")
            return ""
    
    def _extract_text_from_txt(self, file_path: str) -> str:
        """Extract text from TXT file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read().strip()
        except Exception as e:
            logger.error(f"Error extracting text from TXT: {str(e)}")
            return ""
    
    def _chunk_text(self, text: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
        """Split text into overlapping chunks"""
        if not text:
            return []
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + chunk_size
            chunk = text[start:end]
            
            # Try to end at a sentence boundary
            if end < len(text):
                last_period = chunk.rfind('.')
                last_newline = chunk.rfind('\n')
                boundary = max(last_period, last_newline)
                
                if boundary > start + chunk_size // 2:
                    chunk = text[start:start + boundary + 1]
                    end = start + boundary + 1
            
            chunks.append(chunk.strip())
            start = end - overlap
            
            if start >= len(text):
                break
        
        return [chunk for chunk in chunks if chunk]
    
    def _process_document(self, file_path: str) -> bool:
        """Process a document and add it to the RAG system"""
        try:
            # Extract text based on file type
            if file_path.lower().endswith('.pdf'):
                text = self._extract_text_from_pdf(file_path)
            elif file_path.lower().endswith('.txt'):
                text = self._extract_text_from_txt(file_path)
            else:
                logger.error(f"Unsupported file type: {file_path}")
                return False
            
            if not text:
                logger.error(f"No text extracted from file: {file_path}")
                return False
            
            # Get filename
            filename = os.path.basename(file_path)
            
            # Create document record
            doc_id = len(self.documents)
            doc_record = {
                'id': doc_id,
                'filename': filename,
                'file_path': file_path,
                'upload_date': datetime.now(),
                'chunk_count': 0
            }
            
            # Split text into chunks
            chunks = self._chunk_text(text)
            
            if not chunks:
                logger.error(f"No chunks created from file: {file_path}")
                return False
            
            # Create chunk records
            chunk_records = []
            for i, chunk in enumerate(chunks):
                chunk_record = {
                    'doc_id': doc_id,
                    'chunk_id': len(self.document_chunks) + i,
                    'text': chunk,
                    'filename': filename,
                    'chunk_index': i
                }
                chunk_records.append(chunk_record)
            
            # Generate embeddings for chunks
            chunk_texts = [chunk['text'] for chunk in chunk_records]
            embeddings = self.embedding_model.encode(chunk_texts)
            
            # Add embeddings to vector store
            self.vector_store.add(embeddings.astype('float32'))
            
            # Update document and chunk lists
            doc_record['chunk_count'] = len(chunks)
            self.documents.append(doc_record)
            self.document_chunks.extend(chunk_records)
            
            # Save to disk
            self._save_vector_store()
            
            # Save to Firestore
            try:
                self.db.collection('documents').document(str(doc_id)).set({
                    'filename': filename,
                    'file_path': file_path,
                    'upload_date': datetime.now(),
                    'chunk_count': len(chunks)
                })
                logger.info(f"Document saved to Firestore: {filename}")
            except Exception as e:
                logger.error(f"Error saving to Firestore: {str(e)}")
                # Continue even if Firestore save fails
            
            logger.info(f"Document processed successfully: {filename} ({len(chunks)} chunks)")
            return True
            
        except Exception as e:
            logger.error(f"Error processing document {file_path}: {str(e)}")
            return False
    
    def add_document(self, file, department=None, subject=None):
        """Add document to RAG system"""
        # Save file using FileManager
        result = self.file_manager.save_file(
            file, 
            category='notes', 
            department=department,
            metadata={'subject': subject}
        )
        
        if result:
            # Process the document for RAG
            return self._process_document(result['file_path'])
        return False
    
    def get_document_list(self):
        """Get list of available documents"""
        return self.file_manager.list_files(category='notes')
    
    def _retrieve_relevant_chunks(self, query: str, top_k: int = 5) -> List[Dict]:
        """Retrieve most relevant chunks for a query"""
        try:
            if not self.document_chunks:
                return []
            
            # Generate query embedding
            query_embedding = self.embedding_model.encode([query])
            
            # Search in vector store
            scores, indices = self.vector_store.search(query_embedding.astype('float32'), top_k)
            
            # Get relevant chunks
            relevant_chunks = []
            for i, (score, idx) in enumerate(zip(scores[0], indices[0])):
                if idx < len(self.document_chunks):
                    chunk = self.document_chunks[idx].copy()
                    chunk['similarity_score'] = float(score)
                    relevant_chunks.append(chunk)
            
            return relevant_chunks
            
        except Exception as e:
            logger.error(f"Error retrieving chunks: {str(e)}")
            return []
    
    def _generate_response(self, query: str, context_chunks: List[Dict]) -> str:
        """Generate response using Groq with LLaMA"""
        try:
            # Prepare context
            context = "\n\n".join([
                f"From {chunk['filename']}:\n{chunk['text']}"
                for chunk in context_chunks
            ])
            
            # Create prompt
            prompt = f"""Based on the following context from uploaded notes and documents, please answer the question. If the answer cannot be found in the context, say so clearly.

Context:
{context}

Question: {query}

Answer:"""
            
            # Generate response using Groq
            response = self.groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a helpful AI assistant that answers questions based on provided academic notes and documents. Be accurate and cite sources when possible."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.7
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Error generating response: {str(e)}")
            return "I apologize, but I encountered an error while generating a response. Please try again."
    
    def query(self, query: str) -> str:
        """Process a query and return response"""
        try:
            if not query.strip():
                return "Please provide a valid question."
            
            # Retrieve relevant chunks
            relevant_chunks = self._retrieve_relevant_chunks(query, top_k=5)
            
            if not relevant_chunks:
                return "I don't have any relevant information to answer your question. Please make sure notes have been uploaded and try rephrasing your question."
            
            # Generate response
            response = self._generate_response(query, relevant_chunks)
            
            # Log query for analytics
            self._log_query(query, len(relevant_chunks))
            
            return response
            
        except Exception as e:
            logger.error(f"Error processing query: {str(e)}")
            return "I apologize, but I encountered an error while processing your question. Please try again."
    
    def _log_query(self, query: str, num_chunks: int):
        """Log query for analytics"""
        try:
            query_log = {
                'query': query,
                'timestamp': datetime.now(),
                'num_relevant_chunks': num_chunks,
                'total_documents': len(self.documents)
            }
            self.db.collection('query_logs').add(query_log)
        except Exception as e:
            logger.error(f"Error logging query: {str(e)}")
    
    def get_document_list(self) -> List[Dict]:
        """Get list of uploaded documents"""
        try:
            return [
                {
                    'id': doc['id'],
                    'filename': doc['filename'],
                    'upload_date': doc['upload_date'],
                    'chunk_count': doc['chunk_count']
                }
                for doc in self.documents
            ]
        except Exception as e:
            logger.error(f"Error getting document list: {str(e)}")
            return []
    
    def remove_document(self, doc_id: int) -> bool:
        """Remove a document from the system"""
        try:
            if doc_id >= len(self.documents):
                return False
            
            # Remove from documents list
            removed_doc = self.documents.pop(doc_id)
            
            # Remove associated chunks
            self.document_chunks = [
                chunk for chunk in self.document_chunks 
                if chunk['doc_id'] != doc_id
            ]
            
            # Rebuild vector store
            if self.document_chunks:
                embeddings = self.embedding_model.encode([chunk['text'] for chunk in self.document_chunks])
                self.vector_store = faiss.IndexFlatIP(384)
                self.vector_store.add(embeddings.astype('float32'))
            else:
                self.vector_store = faiss.IndexFlatIP(384)
            
            # Save changes
            self._save_vector_store()
            
            # Remove from Firestore
            self.db.collection('documents').document(str(doc_id)).delete()
            
            logger.info(f"Document removed: {removed_doc['filename']}")
            return True
            
        except Exception as e:
            logger.error(f"Error removing document: {str(e)}")
            return False