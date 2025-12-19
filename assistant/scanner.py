"""
File System Scanner for Mac Mini M2
Optimized for M2 architecture with efficient file traversal and analysis.
"""

import os
import stat
import hashlib
import time
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Callable, Optional
import platform

try:
    from .constants import SYSTEM_PATHS
except ImportError:
    from constants import SYSTEM_PATHS


class FileSystemScanner:
    """Scans file system and collects metadata for security analysis."""
    
    def __init__(self):
        self.is_apple_silicon = self._check_apple_silicon()
        self.excluded_paths = {
            '/System/Volumes',
            '/private/var/vm',
            '/.Spotlight-V100',
            '/.fseventsd',
            '/dev',
            '/proc'
        }
        
    def _check_apple_silicon(self) -> bool:
        """Check if running on Apple Silicon (M1/M2/M3) chip."""
        if platform.system() != 'Darwin':
            return False
        try:
            result = subprocess.run(
                ['sysctl', '-n', 'machdep.cpu.brand_string'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return 'Apple M2' in result.stdout or 'Apple M1' in result.stdout
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
            # If we can't determine the chip type, assume it's not Apple Silicon
            return False
    
    def scan(self, path: str, recursive: bool = True, follow_symlinks: bool = False) -> Dict:
        """
        Scan the file system starting from the given path.
        
        Args:
            path: Starting path for scan
            recursive: Whether to scan recursively
            follow_symlinks: Whether to follow symbolic links
            
        Returns:
            Dictionary containing scan results
        """
        start_time = time.time()
        results = {
            'scan_time': datetime.now().isoformat(),
            'start_path': path,
            'platform': platform.platform(),
            'is_apple_silicon': self.is_apple_silicon,
            'files': [],
            'directories': [],
            'symlinks': [],
            'suspicious_files': [],
            'total_files': 0,
            'total_dirs': 0,
            'total_size': 0
        }
        
        path_obj = Path(path)
        if not path_obj.exists():
            raise ValueError(f"Path does not exist: {path}")
        
        self._scan_directory(path_obj, results, recursive, follow_symlinks)
        
        results['scan_duration'] = time.time() - start_time
        return results
    
    def _scan_directory(self, path: Path, results: Dict, recursive: bool, follow_symlinks: bool):
        """Recursively scan a directory."""
        try:
            # Skip excluded paths
            if any(str(path).startswith(excl) for excl in self.excluded_paths):
                return
            
            for item in path.iterdir():
                try:
                    # Handle symbolic links
                    if item.is_symlink():
                        symlink_info = self._get_symlink_info(item)
                        results['symlinks'].append(symlink_info)
                        if not follow_symlinks:
                            continue
                    
                    # Process directories
                    if item.is_dir():
                        dir_info = self._get_directory_info(item)
                        results['directories'].append(dir_info)
                        results['total_dirs'] += 1
                        
                        if recursive:
                            self._scan_directory(item, results, recursive, follow_symlinks)
                    
                    # Process files
                    elif item.is_file():
                        file_info = self._get_file_info(item)
                        results['files'].append(file_info)
                        results['total_files'] += 1
                        results['total_size'] += file_info.get('size', 0)
                        
                        # Check for suspicious files
                        if self._is_suspicious(file_info):
                            results['suspicious_files'].append(file_info)
                
                except PermissionError:
                    # Skip files/directories we don't have permission to access
                    continue
                except Exception as e:
                    # Log error but continue scanning
                    continue
        
        except PermissionError:
            return
        except Exception as e:
            return
    
    def _get_file_info(self, path: Path) -> Dict:
        """Get detailed information about a file."""
        try:
            stats = path.stat()
            
            info = {
                'path': str(path),
                'name': path.name,
                'size': stats.st_size,
                'created': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stats.st_atime).isoformat(),
                'permissions': oct(stats.st_mode)[-3:],
                'owner_uid': stats.st_uid,
                'group_gid': stats.st_gid,
                'is_executable': bool(stats.st_mode & stat.S_IXUSR),
                'is_writable': bool(stats.st_mode & stat.S_IWUSR),
                'extension': path.suffix.lower()
            }
            
            # Calculate file hash for certain file types
            if stats.st_size < 10 * 1024 * 1024:  # Only hash files < 10MB
                if path.suffix.lower() in ['.sh', '.py', '.rb', '.js', '.exe', '.app']:
                    info['hash'] = self._calculate_hash(path)
            
            return info
        
        except Exception as e:
            return {
                'path': str(path),
                'name': path.name,
                'error': str(e)
            }
    
    def _get_directory_info(self, path: Path) -> Dict:
        """Get detailed information about a directory."""
        try:
            stats = path.stat()
            
            return {
                'path': str(path),
                'name': path.name,
                'created': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                'permissions': oct(stats.st_mode)[-3:],
                'owner_uid': stats.st_uid,
                'group_gid': stats.st_gid
            }
        
        except Exception as e:
            return {
                'path': str(path),
                'name': path.name,
                'error': str(e)
            }
    
    def _get_symlink_info(self, path: Path) -> Dict:
        """Get information about a symbolic link."""
        try:
            target = path.resolve()
            
            return {
                'path': str(path),
                'name': path.name,
                'target': str(target),
                'exists': target.exists()
            }
        
        except Exception as e:
            return {
                'path': str(path),
                'name': path.name,
                'error': str(e)
            }
    
    def _calculate_hash(self, path: Path) -> str:
        """Calculate SHA256 hash of a file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (IOError, OSError, PermissionError):
            return None
    
    def _is_suspicious(self, file_info: Dict) -> bool:
        """Check if a file appears suspicious."""
        suspicious_indicators = []
        
        # Check for suspicious extensions (excluding .app in common app directories)
        path = file_info.get('path', '')
        suspicious_extensions = ['.sh', '.command', '.pkg', '.dmg', '.exe']
        
        # Add .app only if not in Applications or system directories
        if not any(app_dir in path for app_dir in ['/Applications/', '/System/Applications/']):
            suspicious_extensions.append('.app')
        
        if file_info.get('extension') in suspicious_extensions:
            suspicious_indicators.append('suspicious_extension')
        
        # Check for world-writable files
        perms = file_info.get('permissions', '000')
        if len(perms) == 3 and perms[2] in ['2', '3', '6', '7']:
            suspicious_indicators.append('world_writable')
        
        # Check for hidden executable files
        if file_info.get('name', '').startswith('.') and file_info.get('is_executable'):
            suspicious_indicators.append('hidden_executable')
        
        # Check for root-owned executables only in non-system locations
        if (file_info.get('is_executable') and 
            file_info.get('owner_uid') == 0 and
            not any(sys_path in path for sys_path in SYSTEM_PATHS)):
            suspicious_indicators.append('root_owned_executable')
        
        return len(suspicious_indicators) > 0
    
    def monitor(self, path: str, interval: int, callback: Callable):
        """
        Continuously monitor a path for changes.
        
        Args:
            path: Path to monitor
            interval: Check interval in seconds
            callback: Function to call when changes detected
        """
        previous_scan = self.scan(path, recursive=True)
        
        while True:
            time.sleep(interval)
            current_scan = self.scan(path, recursive=True)
            
            # Compare scans and report changes
            changes = self._compare_scans(previous_scan, current_scan)
            
            for change in changes:
                callback(change)
            
            previous_scan = current_scan
    
    def _compare_scans(self, old_scan: Dict, new_scan: Dict) -> List[Dict]:
        """Compare two scans and identify changes."""
        changes = []
        
        # Create sets of file paths for comparison
        old_files = {f['path'] for f in old_scan.get('files', [])}
        new_files = {f['path'] for f in new_scan.get('files', [])}
        
        # Find new files
        for path in new_files - old_files:
            file_info = next(f for f in new_scan['files'] if f['path'] == path)
            changes.append({
                'type': 'file_created',
                'path': path,
                'info': file_info,
                'risk_level': 'medium' if self._is_suspicious(file_info) else 'low'
            })
        
        # Find deleted files
        for path in old_files - new_files:
            changes.append({
                'type': 'file_deleted',
                'path': path,
                'risk_level': 'low'
            })
        
        # Find modified files (compare modification times)
        for path in old_files & new_files:
            old_file = next(f for f in old_scan['files'] if f['path'] == path)
            new_file = next(f for f in new_scan['files'] if f['path'] == path)
            
            if old_file.get('modified') != new_file.get('modified'):
                changes.append({
                    'type': 'file_modified',
                    'path': path,
                    'info': new_file,
                    'risk_level': 'medium' if self._is_suspicious(new_file) else 'low'
                })
        
        return changes
