import os
import shutil
from datetime import datetime
from pathlib import Path
from werkzeug.utils import secure_filename
import hashlib
import json

class FileManager:
    def __init__(self, base_path='uploads'):
        self.base_path = Path(base_path)
        self.notes_path = self.base_path / 'notes'
        self.documents_path = self.base_path / 'documents'
        self.temp_path = self.base_path / 'temp'
        
        # Create directories if they don't exist
        for path in [self.notes_path, self.documents_path, self.temp_path]:
            path.mkdir(parents=True, exist_ok=True)
    
    def save_file(self, file, category='notes', department=None, metadata=None):
        """Save uploaded file with metadata"""
        if not file or not file.filename:
            return None
        
        # Secure filename
        filename = secure_filename(file.filename)
        
        # Generate unique filename to avoid conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name, ext = os.path.splitext(filename)
        unique_filename = f"{name}{ext}"
        
        # Determine storage path
        if category == 'notes' and department:
            storage_path = self.notes_path / department.lower()
        elif category == 'documents':
            storage_path = self.documents_path
        else:
            storage_path = self.notes_path
        
        storage_path.mkdir(parents=True, exist_ok=True)
        file_path = storage_path / unique_filename
        
        # Save the file first
        try:
            file.save(str(file_path))
        except Exception as e:
            print(f"Error saving file: {e}")
            return None
        
        # Generate file hash after saving
        file_hash = self._generate_file_hash(file_path)
        
        # Save metadata after file is saved
        metadata_info = {
            'original_filename': filename,
            'stored_filename': unique_filename,
            'file_path': str(file_path),
            'category': category,
            'department': department,
            'upload_date': datetime.now().isoformat(),
            'file_size': os.path.getsize(file_path),
            'file_hash': file_hash,
            'metadata': metadata or {}
        }
        
        self._save_metadata(unique_filename, metadata_info)
        
        return {
            'filename': unique_filename,
            'file_path': str(file_path),
            'metadata': metadata_info
        }
    
    def get_file_path(self, filename):
        """Get full path of a file"""
        metadata = self._load_metadata(filename)
        if metadata:
            return metadata['file_path']
        return None
    
    def delete_file(self, filename):
        """Delete file and its metadata"""
        metadata = self._load_metadata(filename)
        if metadata:
            file_path = metadata['file_path']
            if os.path.exists(file_path):
                os.remove(file_path)
            self._delete_metadata(filename)
            return True
        return False
    
    def list_files(self, category=None, department=None):
        """List files with optional filtering"""
        metadata_dir = self.base_path / 'metadata'
        if not metadata_dir.exists():
            return []
        
        files = []
        for metadata_file in metadata_dir.glob('*.json'):
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
                
            # Apply filters
            if category and metadata.get('category') != category:
                continue
            if department and metadata.get('department') != department:
                continue
                
            files.append(metadata)
        
        return sorted(files, key=lambda x: x['upload_date'], reverse=True)
    
    def _generate_file_hash(self, file_path):
        """Generate MD5 hash of file for integrity checking"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def _save_metadata(self, filename, metadata):
        """Save file metadata as JSON"""
        metadata_dir = self.base_path / 'metadata'
        metadata_dir.mkdir(exist_ok=True)
        
        metadata_file = metadata_dir / f"{filename}.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def _load_metadata(self, filename):
        """Load file metadata"""
        metadata_dir = self.base_path / 'metadata'
        metadata_file = metadata_dir / f"{filename}.json"
        
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                return json.load(f)
        return None
    
    def _delete_metadata(self, filename):
        """Delete file metadata"""
        metadata_dir = self.base_path / 'metadata'
        metadata_file = metadata_dir / f"{filename}.json"
        
        if metadata_file.exists():
            os.remove(metadata_file)
