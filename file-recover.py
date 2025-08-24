#!/usr/bin/env python3
"""
Enhanced File Recovery Tool - A non-destructive file recovery utility
Recovers deleted files and files from formatted/corrupted drives
Works on Kali Linux and Windows
"""

import os
import sys
import argparse
import logging
import struct
import zlib
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import tqdm
import pytsk3

# Try to import pyewf (may not be available on all systems)
try:
    import pyewf
    HAS_EWF = True
except ImportError:
    HAS_EWF = False
    print("Warning: pyewf not available. EWF file support disabled.")

# Supported file signatures with proper handling for duplicates
FILE_SIGNATURES = [
    # Documents
    (b'\x50\x4B\x03\x04', 0, 'zip_based', 10000000),  # ZIP-based formats (DOCX, XLSX, PPTX)
    (b'\xD0\xCF\x11\xE0', 0, 'cfb', 50000000),        # Compound File Binary (DOC, XLS, PPT)
    (b'\x25\x50\x44\x46', 0, 'pdf', 100000000),       # PDF
    (b'\x50\x4B\x05\x06', 0, 'zip_based', 10000000),  # ZIP empty archive
    (b'\x50\x4B\x07\x08', 0, 'zip_based', 10000000),  # ZIP spanned archive
    
    # Images
    (b'\xFF\xD8\xFF', 0, 'jpg', 30000000),
    (b'\x89\x50\x4E\x47', 0, 'png', 50000000),
    (b'\x47\x49\x46\x38', 0, 'gif', 10000000),
    (b'\x42\x4D', 0, 'bmp', 100000000),
    (b'\x49\x49\x2A\x00', 0, 'tiff', 100000000),  # Little-endian
    (b'\x4D\x4D\x00\x2A', 0, 'tiff', 100000000),  # Big-endian
    
    # Video
    (b'\x00\x00\x00\x18\x66\x74\x79\x70', 4, 'mp4', 500000000),  # MP4
    (b'\x52\x49\x46\x46', 0, 'avi', 500000000),   # AVI/RIFF
    (b'\x1A\x45\xDF\xA3', 0, 'mkv', 500000000),   # Matroska
    (b'\x66\x74\x79\x70', 4, 'mov', 500000000),   # QuickTime
    (b'\x46\x4C\x56\x01', 0, 'flv', 100000000),   # FLV
    
    # Audio
    (b'\x49\x44\x33', 0, 'mp3', 10000000),       # ID3 tag
    (b'\xFF\xFB', 0, 'mp3', 10000000),           # MPEG layer 3
    (b'\x52\x49\x46\x46', 0, 'wav', 100000000),  # WAV
    (b'\xFF\xF1', 0, 'aac', 10000000),           # AAC
    (b'\x66\x4C\x61\x43', 0, 'flac', 100000000), # FLAC
    
    # Archives
    (b'\x52\x61\x72\x21\x1A\x07\x00', 0, 'rar', 100000000),  # RAR
    (b'\x52\x61\x72\x21\x1A\x07\x01\x00', 0, 'rar5', 100000000),  # RAR5
    (b'\x37\x7A\xBC\xAF\x27\x1C', 0, '7z', 100000000),      # 7Z
    
    # Others
    (b'\x3C\x21\x44\x4F\x43\x54', 0, 'html', 1000000),  # <!DOCT
    (b'\x2F\x2A\x20\x43\x53\x53', 0, 'css', 1000000),   # /* CSS
    (b'\x3C\x73\x63\x72\x69\x70', 0, 'js', 1000000),    # <scrip
    (b'\x4D\x5A', 0, 'exe', 50000000),                  # EXE
]

# Extension mapping based on file type
EXTENSION_MAP = {
    'zip_based': '.zip_or_office',
    'cfb': '.cfb_file',
    'pdf': '.pdf',
    'jpg': '.jpg',
    'png': '.png',
    'gif': '.gif',
    'bmp': '.bmp',
    'tiff': '.tiff',
    'mp4': '.mp4',
    'avi': '.avi',
    'mkv': '.mkv',
    'mov': '.mov',
    'flv': '.flv',
    'mp3': '.mp3',
    'wav': '.wav',
    'aac': '.aac',
    'flac': '.flac',
    'rar': '.rar',
    'rar5': '.rar',
    '7z': '.7z',
    'html': '.html',
    'css': '.css',
    'js': '.js',
    'exe': '.exe'
}

class EWFImgInfo(pytsk3.Img_Info):
    """Wrapper for EWF files to work with pytsk3"""
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__()
        
    def close(self):
        self._ewf_handle.close()
        
    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)
        
    def get_size(self):
        return self._ewf_handle.get_media_size()

class FileRecoveryTool:
    def __init__(self):
        self.output_dir = None
        self.log_file = None
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(f"recovery_output_{timestamp}")
        self.output_dir.mkdir(exist_ok=True)
        
        self.log_file = self.output_dir / "recovery.log"
        logging.basicConfig(
            filename=str(self.log_file),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        console.setFormatter(formatter)
        logging.getLogger().addHandler(console)
        
    def validate_source(self, source_path):
        """Validate the source path exists and is accessible"""
        if not os.path.exists(source_path):
            logging.error(f"Source path {source_path} does not exist")
            return False
            
        # Check if we have read access
        if not os.access(source_path, os.R_OK):
            logging.error(f"No read access to {source_path}")
            return False
            
        return True
        
    def get_filesystem_handle(self, source_path):
        """Get a filesystem handle using pytsk3"""
        try:
            if HAS_EWF and source_path.lower().endswith(('.e01', '.ewf')):
                # Handle EWF files
                filenames = pyewf.glob(source_path)
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                img_info = EWFImgInfo(ewf_handle)
            else:
                # Handle regular files/devices
                img_info = pytsk3.Img_Info(source_path)
                
            fs_info = pytsk3.FS_Info(img_info)
            return fs_info, img_info
        except Exception as e:
            logging.error(f"Error accessing filesystem: {e}")
            return None, None
            
    def walk_directory(self, directory, recursive=True):
        """Recursively walk through directory and yield files"""
        try:
            for fs_object in directory:
                if fs_object.info.name.name in [b".", b".."]:
                    continue
                    
                if hasattr(fs_object.info.meta, 'type'):
                    if fs_object.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        if recursive:
                            try:
                                subdir = fs_object.as_directory()
                                yield from self.walk_directory(subdir, recursive)
                            except Exception as e:
                                logging.warning(f"Error accessing subdirectory: {e}")
                                continue
                    elif fs_object.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                        yield fs_object
        except Exception as e:
            logging.warning(f"Error walking directory: {e}")
            
    def recover_deleted_files(self, source_path, filters=None, recursive=True):
        """Recover deleted files using filesystem metadata"""
        logging.info(f"Starting deleted file recovery from {source_path}")
        
        if not self.validate_source(source_path):
            return False
            
        fs_info, img_info = self.get_filesystem_handle(source_path)
        if not fs_info:
            return False
            
        # Create output subdirectory
        output_subdir = self.output_dir / "deleted_files"
        output_subdir.mkdir(exist_ok=True)
        
        recovered_count = 0
        
        try:
            # Walk through the filesystem recursively
            root_dir = fs_info.open_dir(path="/")
            
            for fs_object in tqdm.tqdm(self.walk_directory(root_dir, recursive), 
                                 desc="Scanning filesystem", unit="files"):
                # Check if file is deleted
                if hasattr(fs_object.info.meta, 'flags') and \
                   fs_object.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                    
                    try:
                        file_name = fs_object.info.name.name.decode('utf-8', errors='replace')
                        file_size = fs_object.info.meta.size
                        
                        # Get file metadata
                        mtime = fs_object.info.meta.mtime
                        if mtime:
                            timestamp = datetime.utcfromtimestamp(mtime).strftime('%Y%m%d_%H%M%S')
                        else:
                            timestamp = "unknown_time"
                            
                        # Apply filters if provided
                        if filters and not self._passes_filters(file_name, file_size, filters):
                            continue
                            
                        # Create unique filename with metadata
                        base_name = f"{timestamp}_{file_size}_{file_name}"
                        safe_name = "".join(c for c in base_name if c.isalnum() or c in '._- ').rstrip()
                        if not safe_name:
                            safe_name = f"file_{recovered_count:06d}"
                            
                        # Recover the file
                        if self._recover_file(fs_object, output_subdir, safe_name, file_size):
                            recovered_count += 1
                            logging.info(f"Recovered: {file_name} ({file_size} bytes)")
                            
                    except Exception as e:
                        logging.warning(f"Error processing file: {e}")
                        continue
                        
            logging.info(f"Deleted file recovery completed. Recovered {recovered_count} files.")
            return True
            
        except Exception as e:
            logging.error(f"Error during deleted file recovery: {e}")
            return False
        finally:
            try:
                if img_info:
                    img_info.close()
            except:
                pass
                
    def recover_full_drive(self, source_path, filters=None, chunk_size=64*1024*1024):
        """Recover files using file carving techniques with chunked reading"""
        logging.info(f"Starting full drive recovery from {source_path}")
        
        if not self.validate_source(source_path):
            return False
            
        # Create output subdirectory
        output_subdir = self.output_dir / "carved_files"
        output_subdir.mkdir(exist_ok=True)
        
        file_handle = None
        try:
            # Get file size and set up progress tracking
            if HAS_EWF and source_path.lower().endswith(('.e01', '.ewf')):
                filenames = pyewf.glob(source_path)
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                file_size = ewf_handle.get_media_size()
                file_handle = ewf_handle
            else:
                file_size = os.path.getsize(source_path)
                file_handle = open(source_path, 'rb')
                
            # Scan for files in chunks
            recovered_count = self._carve_files_chunked(file_handle, file_size, chunk_size, output_subdir, filters)
            
            logging.info(f"Full drive recovery completed. Recovered {recovered_count} files.")
            return True
            
        except Exception as e:
            logging.error(f"Error during full drive recovery: {e}")
            return False
        finally:
            try:
                if file_handle:
                    file_handle.close()
            except:
                pass
                
    def _carve_files_chunked(self, file_handle, file_size, chunk_size, output_dir, filters):
        """Carve files from device using chunked reading"""
        recovered_count = 0
        position = 0
        buffer = b''
        buffer_size = max(len(sig) + offset for sig, offset, _, _ in FILE_SIGNATURES) + 1024
        
        # Create progress bar
        with tqdm.tqdm(total=file_size, unit='B', unit_scale=True, desc="Scanning") as pbar:
            while position < file_size:
                # Read chunk
                read_size = min(chunk_size, file_size - position)
                chunk = file_handle.read(read_size)
                if not chunk:
                    break
                    
                # Add to buffer
                buffer += chunk
                if len(buffer) > buffer_size * 2:
                    buffer = buffer[-buffer_size:]
                
                # Scan buffer for signatures
                buffer_pos = 0
                while buffer_pos < len(buffer) - 16:  # Minimum signature length
                    found = False
                    
                    for signature, offset, file_type, max_size in FILE_SIGNATURES:
                        sig_len = len(signature)
                        if buffer_pos + sig_len <= len(buffer) and \
                           buffer[buffer_pos:buffer_pos + sig_len] == signature:
                            
                            # Calculate actual file position
                            file_pos = position - len(buffer) + buffer_pos + offset
                            
                            # Carve the file
                            carved_data = self._carve_file_at_position(
                                file_handle, file_pos, file_type, max_size, file_size)
                            
                            if carved_data:
                                # Create unique filename
                                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                                file_name = f"carved_{timestamp}_{file_pos:012x}_{recovered_count:06d}{EXTENSION_MAP.get(file_type, '.bin')}"
                                
                                # Apply filters
                                if filters and not self._passes_filters(file_name, len(carved_data), filters):
                                    continue
                                    
                                # Save file
                                file_path = output_dir / file_name
                                with open(file_path, 'wb') as f:
                                    f.write(carved_data)
                                    
                                logging.info(f"Carved: {file_name} ({len(carved_data)} bytes)")
                                recovered_count += 1
                                
                                # Skip ahead in buffer to avoid overlapping files
                                buffer_pos += len(carved_data)
                                found = True
                                break
                    
                    if not found:
                        buffer_pos += 1
                
                # Update progress
                position += read_size
                pbar.update(read_size)
                
        return recovered_count
        
    def _carve_file_at_position(self, file_handle, position, file_type, max_size, total_size):
        """Carve a file from a specific position using appropriate method"""
        try:
            file_handle.seek(position)
            
            if file_type == 'jpg':
                return self._carve_jpg(file_handle, max_size)
            elif file_type == 'png':
                return self._carve_png(file_handle, max_size)
            elif file_type == 'pdf':
                return self._carve_pdf(file_handle, max_size)
            elif file_type == 'mp4':
                return self._carve_mp4(file_handle, max_size)
            elif file_type == 'avi':
                return self._carve_avi(file_handle, max_size)
            elif file_type == 'zip_based':
                return self._carve_zip_based(file_handle, max_size)
            elif file_type == 'cfb':
                return self._carve_cfb(file_handle, max_size)
            else:
                # Default carving for other file types
                return self._carve_generic(file_handle, max_size)
        except Exception as e:
            logging.warning(f"Error carving file at position {position}: {e}")
            return None
            
    def _carve_jpg(self, file_handle, max_size):
        """Carve JPEG file by finding EOI marker"""
        start_pos = file_handle.tell()
        data = file_handle.read(min(8192, max_size))
        eoi_pos = data.find(b'\xFF\xD9')
        
        if eoi_pos != -1:
            file_handle.seek(start_pos)
            return file_handle.read(eoi_pos + 2)
        return None
        
    def _carve_png(self, file_handle, max_size):
        """Carve PNG file by finding IEND chunk"""
        start_pos = file_handle.tell()
        data = file_handle.read(min(65536, max_size))
        iend_pos = data.find(b'IEND')
        
        if iend_pos != -1:
            # IEND chunk is 12 bytes total (4 byte length, 4 byte type, 4 byte CRC)
            file_handle.seek(start_pos)
            return file_handle.read(iend_pos + 12)
        return None
        
    def _carve_pdf(self, file_handle, max_size):
        """Carve PDF file by finding %%EOF"""
        start_pos = file_handle.tell()
        data = file_handle.read(min(131072, max_size))
        eof_pos = data.find(b'%%EOF')
        
        if eof_pos != -1:
            file_handle.seek(start_pos)
            return file_handle.read(eof_pos + 5)  # %%EOF is 5 bytes
        return None
        
    def _carve_mp4(self, file_handle, max_size):
        """Carve MP4 file by parsing box structure"""
        start_pos = file_handle.tell()
        try:
            # Read and parse MP4 boxes to find the end
            pos = start_pos
            while pos < start_pos + max_size:
                file_handle.seek(pos)
                header = file_handle.read(8)
                if len(header) < 8:
                    break
                    
                size = struct.unpack('>I', header[0:4])[0]
                box_type = header[4:8]
                
                if size == 0:  # Box extends to end of file
                    break
                if size == 1:  # Extended size
                    extended_size = struct.unpack('>Q', file_handle.read(8))[0]
                    pos += extended_size
                else:
                    pos += size
                    
                # Stop at mdat box (often very large)
                if box_type == b'mdat':
                    break
                    
            file_handle.seek(start_pos)
            return file_handle.read(pos - start_pos)
        except:
            return None
            
    def _carve_avi(self, file_handle, max_size):
        """Carve AVI file by parsing RIFF structure"""
        start_pos = file_handle.tell()
        try:
            pos = start_pos
            while pos < start_pos + max_size:
                file_handle.seek(pos)
                chunk_header = file_handle.read(8)
                if len(chunk_header) < 8:
                    break
                    
                chunk_id = chunk_header[0:4]
                chunk_size = struct.unpack('<I', chunk_header[4:8])[0]
                
                if chunk_id == b'RIFF' and chunk_size >= 4:
                    # Check if it's AVI
                    form_type = file_handle.read(4)
                    if form_type != b'AVI ':
                        break
                elif chunk_id == b'LIST':
                    # LIST chunk
                    list_type = file_handle.read(4)
                elif chunk_id in [b'JUNK', b'INFO']:
                    # Skip these chunks
                    pass
                    
                pos += chunk_size + 8
                
            file_handle.seek(start_pos)
            return file_handle.read(pos - start_pos)
        except:
            return None
            
    def _carve_zip_based(self, file_handle, max_size):
        """Carve ZIP-based files (Office documents, archives)"""
        start_pos = file_handle.tell()
        try:
            # Read central directory end record
            file_handle.seek(start_pos + max_size - 65536)  # Search near end
            data = file_handle.read(65536)
            eocd_pos = data.find(b'\x50\x4B\x05\x06')
            
            if eocd_pos != -1:
                # Found end of central directory
                eocd = data[eocd_pos:eocd_pos+22]
                central_dir_size = struct.unpack('<I', eocd[12:16])[0]
                central_dir_offset = struct.unpack('<I', eocd[16:20])[0]
                
                file_handle.seek(start_pos)
                return file_handle.read(central_dir_offset + central_dir_size + 22)
        except:
            pass
            
        return None
        
    def _carve_cfb(self, file_handle, max_size):
        """Carve Compound File Binary files"""
        start_pos = file_handle.tell()
        try:
            # CFB files have a specific structure with sector allocation
            # This is a simplified approach
            file_handle.seek(start_pos + 512)  # Skip header
            data = file_handle.read(4096)
            
            # Look for typical CFB patterns
            if b'Root Entry' in data or b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' in data:
                file_handle.seek(start_pos)
                return file_handle.read(max_size)
        except:
            pass
            
        return None
        
    def _carve_generic(self, file_handle, max_size):
        """Generic file carving using maximum size"""
        start_pos = file_handle.tell()
        return file_handle.read(max_size)
        
    def _recover_file(self, fs_object, output_dir, file_name, file_size):
        """Recover a single file using filesystem metadata"""
        try:
            # Handle duplicate filenames
            output_path = output_dir / file_name
            counter = 1
            while output_path.exists():
                name_parts = os.path.splitext(file_name)
                output_path = output_dir / f"{name_parts[0]}_{counter}{name_parts[1]}"
                counter += 1
                
            # Read and save the file
            with open(output_path, 'wb') as out_file:
                offset = 0
                remaining_size = file_size
                
                while remaining_size > 0:
                    available_size = min(1024 * 1024, remaining_size)  # Read in 1MB chunks
                    data = fs_object.read_random(offset, available_size)
                    if not data:
                        break
                        
                    out_file.write(data)
                    offset += len(data)
                    remaining_size -= len(data)
                    
            return True
            
        except Exception as e:
            logging.error(f"Error recovering file {file_name}: {e}")
            return False
            
    def _passes_filters(self, file_name, file_size, filters):
        """Check if a file passes the provided filters"""
        if 'extensions' in filters and filters['extensions']:
            file_ext = os.path.splitext(file_name)[1].lower()
            if file_ext not in filters['extensions']:
                return False
                
        if 'name_substring' in filters and filters['name_substring']:
            if filters['name_substring'].lower() not in file_name.lower():
                return False
                
        if 'max_size' in filters and file_size > filters['max_size']:
            return False
            
        return True

def show_banner():
    """Display tool banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║               ENHANCED FILE RECOVERY TOOL                    ║
    ║                  Kali Linux & Windows                        ║
    ║         Deleted File Recovery & File Carving Utility         ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def show_help():
    """Display help information"""
    help_text = """
    Usage:
      file_recovery_tool.py <source> [options]
    
    Modes:
      -m, --mode MODE          Recovery mode: 'deleted' or 'full'
    
    Filters:
      -e, --extensions EXT     File extensions to recover (e.g., jpg docx pdf)
      -n, --name NAME          Filename substring to search for
      -s, --max-size SIZE      Maximum file size in bytes
    
    Options:
      --no-recursive           Disable recursive directory scanning
      --chunk-size SIZE        Chunk size in MB for carving (default: 64)
      --help                   Show this help message
    
    Examples:
      # Recover deleted files from a drive
      file_recovery_tool.py /dev/sdb1 -m deleted -e jpg pdf docx
      
      # Full drive carving with filters
      file_recovery_tool.py /dev/sdb1 -m full -n "important" -s 10000000
      
      # Recover from EWF image
      file_recovery_tool.py image.E01 -m deleted
    """
    print(help_text)

def interactive_menu():
    """Interactive CLI menu for the tool"""
    show_banner()
    
    while True:
        print("\n" + "="*60)
        print("ENHANCED FILE RECOVERY TOOL - MAIN MENU")
        print("="*60)
        print("1. Recover Deleted Files (using filesystem metadata)")
        print("2. Full Drive Carving (file signature scanning)")
        print("3. Show Help")
        print("4. Exit")
        print("="*60)
        
        choice = input("\nSelect an option (1-4): ").strip()
        
        if choice == "1":
            source = input("Enter source path (drive or image): ").strip()
            if not source:
                print("Error: Source path is required!")
                continue
                
            recursive = input("Recursive scanning? (y/n, default y): ").strip().lower()
            recursive = recursive != 'n'
            
            extensions = input("File extensions to recover (comma separated, leave empty for all): ").strip()
            name_filter = input("Filename contains (leave empty for all): ").strip()
            max_size = input("Maximum file size in bytes (leave empty for no limit): ").strip()
            
            filters = {}
            if extensions:
                filters['extensions'] = [ext.strip().lower() if ext.strip().startswith('.') else f".{ext.strip().lower()}" 
                                       for ext in extensions.split(',')]
            if name_filter:
                filters['name_substring'] = name_filter
            if max_size:
                try:
                    filters['max_size'] = int(max_size)
                except ValueError:
                    print("Invalid size, ignoring max size filter")
            
            tool = FileRecoveryTool()
            tool.recover_deleted_files(source, filters, recursive)
            
        elif choice == "2":
            source = input("Enter source path (drive or image): ").strip()
            if not source:
                print("Error: Source path is required!")
                continue
                
            chunk_size = input("Chunk size in MB (default 64): ").strip()
            try:
                chunk_size = int(chunk_size) * 1024 * 1024 if chunk_size else 64 * 1024 * 1024
            except ValueError:
                print("Invalid chunk size, using default 64MB")
                chunk_size = 64 * 1024 * 1024
            
            extensions = input("File extensions to recover (comma separated, leave empty for all): ").strip()
            name_filter = input("Filename contains (leave empty for all): ").strip()
            max_size = input("Maximum file size in bytes (leave empty for no limit): ").strip()
            
            filters = {}
            if extensions:
                filters['extensions'] = [ext.strip().lower() if ext.strip().startswith('.') else f".{ext.strip().lower()}" 
                                       for ext in extensions.split(',')]
            if name_filter:
                filters['name_substring'] = name_filter
            if max_size:
                try:
                    filters['max_size'] = int(max_size)
                except ValueError:
                    print("Invalid size, ignoring max size filter")
            
            tool = FileRecoveryTool()
            tool.recover_full_drive(source, filters, chunk_size)
            
        elif choice == "3":
            show_help()
            
        elif choice == "4":
            print("Exiting... Goodbye!")
            break
            
        else:
            print("Invalid choice! Please select 1-4.")

def main():
    """Main function with CLI interface"""
    parser = argparse.ArgumentParser(description="Enhanced File Recovery Tool", add_help=False)
    parser.add_argument("source", nargs="?", help="Source drive or image path")
    parser.add_argument("-m", "--mode", choices=["deleted", "full"],
                       help="Recovery mode: deleted files or full drive carving")
    parser.add_argument("-e", "--extensions", nargs="+",
                       help="File extensions to recover (e.g., jpg docx)")
    parser.add_argument("-n", "--name", 
                       help="Filename substring to search for")
    parser.add_argument("-s", "--max-size", type=int,
                       help="Maximum file size in bytes")
    parser.add_argument("--no-recursive", action="store_true",
                       help="Disable recursive directory scanning")
    parser.add_argument("--chunk-size", type=int, default=64,
                       help="Chunk size in MB for carving (default: 64MB)")
    parser.add_argument("--interactive", action="store_true",
                       help="Start interactive mode")
    parser.add_argument("--help", action="store_true",
                       help="Show help message")
    
    # If no arguments provided, show interactive menu
    if len(sys.argv) == 1:
        interactive_menu()
        return
    
    args = parser.parse_args()
    
    if args.help:
        show_help()
        return
        
    if args.interactive:
        interactive_menu()
        return
        
    if not args.source:
        print("Error: Source path is required!")
        show_help()
        sys.exit(1)
        
    if not args.mode:
        print("Error: Recovery mode is required!")
        show_help()
        sys.exit(1)
    
    # Prepare filters
    filters = {}
    if args.extensions:
        filters['extensions'] = [ext.lower() if ext.startswith('.') else f".{ext.lower()}" 
                               for ext in args.extensions]
    if args.name:
        filters['name_substring'] = args.name
    if args.max_size:
        filters['max_size'] = args.max_size
        
    # Initialize recovery tool
    tool = FileRecoveryTool()
    
    # Perform recovery based on mode
    if args.mode == "deleted":
        success = tool.recover_deleted_files(args.source, filters, not args.no_recursive)
    else:
        success = tool.recover_full_drive(args.source, filters, args.chunk_size * 1024 * 1024)
        
    if success:
        print(f"Recovery completed. Files saved to: {tool.output_dir}")
        print(f"Log file: {tool.log_file}")
    else:
        print("Recovery failed. Check log for details.")
        sys.exit(1)
        
if __name__ == "__main__":
    main()