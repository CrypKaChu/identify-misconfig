"""Cache management utilities for API results."""

import os
import json
import pickle
import hashlib
from typing import Any, Dict, Optional, Union, List
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class CacheManager:
    """Manages caching of API results to reduce API usage and improve performance."""
    
    def __init__(self, cache_dir: str = '.cache', default_ttl_hours: int = 24):
        """Initialize cache manager.
        
        Args:
            cache_dir: Directory to store cache files
            default_ttl_hours: Default time-to-live for cache entries in hours
        """
        self.cache_dir = cache_dir
        self.default_ttl_hours = default_ttl_hours
        self.metadata_file = os.path.join(cache_dir, 'cache_metadata.json')
        
        # Ensure cache directory exists
        os.makedirs(cache_dir, exist_ok=True)
        
        # Load existing metadata
        self.metadata = self._load_metadata()
    
    def _load_metadata(self) -> Dict[str, Any]:
        """Load cache metadata from file.
        
        Returns:
            Cache metadata dictionary
        """
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load cache metadata: {e}")
        
        return {}
    
    def _save_metadata(self):
        """Save cache metadata to file."""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except IOError as e:
            logger.error(f"Failed to save cache metadata: {e}")
    
    def _generate_cache_key(self, query: str, api_type: str = 'shodan') -> str:
        """Generate a unique cache key for a query.
        
        Args:
            query: Search query string
            api_type: Type of API (shodan, censys)
            
        Returns:
            Unique cache key
        """
        # Create hash of query and API type
        key_string = f"{api_type}:{query}"
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _get_cache_file_path(self, cache_key: str) -> str:
        """Get the file path for a cache entry.
        
        Args:
            cache_key: Unique cache key
            
        Returns:
            Path to cache file
        """
        return os.path.join(self.cache_dir, f"{cache_key}.json")
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if a cache entry is still valid.
        
        Args:
            cache_key: Unique cache key
            
        Returns:
            True if cache is valid, False otherwise
        """
        if cache_key not in self.metadata:
            return False
        
        entry = self.metadata[cache_key]
        created_time = datetime.fromisoformat(entry['created_at'])
        ttl_hours = entry.get('ttl_hours', self.default_ttl_hours)
        
        # Check if cache has expired
        expiry_time = created_time + timedelta(hours=ttl_hours)
        return datetime.now() < expiry_time
    
    def get(self, query: str, api_type: str = 'shodan') -> Optional[Dict[str, Any]]:
        """Retrieve cached results for a query.
        
        Args:
            query: Search query string
            api_type: Type of API (shodan, censys)
            
        Returns:
            Cached results if valid, None otherwise
        """
        cache_key = self._generate_cache_key(query, api_type)
        
        # Check if cache exists and is valid
        if not self._is_cache_valid(cache_key):
            logger.debug(f"Cache miss for query: {query}")
            return None
        
        cache_file = self._get_cache_file_path(cache_key)
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            logger.debug(f"Cache hit for query: {query}")
            return data
            
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to read cache file {cache_file}: {e}")
            # Remove invalid cache entry
            self._remove_cache_entry(cache_key)
            return None
    
    def set(self, query: str, data: Dict[str, Any], 
            api_type: str = 'shodan', ttl_hours: Optional[int] = None) -> bool:
        """Store results in cache.
        
        Args:
            query: Search query string
            data: Results data to cache
            api_type: Type of API (shodan, censys)
            ttl_hours: Time-to-live in hours (uses default if None)
            
        Returns:
            True if successful, False otherwise
        """
        cache_key = self._generate_cache_key(query, api_type)
        cache_file = self._get_cache_file_path(cache_key)
        
        try:
            # Save data to file
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Update metadata
            self.metadata[cache_key] = {
                'query': query,
                'api_type': api_type,
                'created_at': datetime.now().isoformat(),
                'ttl_hours': ttl_hours or self.default_ttl_hours,
                'file_size': os.path.getsize(cache_file),
                'result_count': len(data.get('results', []))
            }
            
            self._save_metadata()
            logger.debug(f"Cached results for query: {query}")
            return True
            
        except IOError as e:
            logger.error(f"Failed to cache results for query {query}: {e}")
            return False
    
    def _remove_cache_entry(self, cache_key: str):
        """Remove a cache entry and its file.
        
        Args:
            cache_key: Unique cache key
        """
        cache_file = self._get_cache_file_path(cache_key)
        
        # Remove cache file
        try:
            if os.path.exists(cache_file):
                os.remove(cache_file)
        except IOError as e:
            logger.warning(f"Failed to remove cache file {cache_file}: {e}")
        
        # Remove from metadata
        if cache_key in self.metadata:
            del self.metadata[cache_key]
            self._save_metadata()
    
    def invalidate(self, query: str, api_type: str = 'shodan'):
        """Invalidate cache for a specific query.
        
        Args:
            query: Search query string
            api_type: Type of API (shodan, censys)
        """
        cache_key = self._generate_cache_key(query, api_type)
        self._remove_cache_entry(cache_key)
        logger.info(f"Invalidated cache for query: {query}")
    
    def invalidate_by_pattern(self, pattern: str):
        """Invalidate cache entries matching a pattern.
        
        Args:
            pattern: Pattern to match against queries
        """
        keys_to_remove = []
        
        for cache_key, entry in self.metadata.items():
            if pattern.lower() in entry.get('query', '').lower():
                keys_to_remove.append(cache_key)
        
        for key in keys_to_remove:
            self._remove_cache_entry(key)
        
        logger.info(f"Invalidated {len(keys_to_remove)} cache entries matching pattern: {pattern}")
    
    def clear_all(self):
        """Clear all cache entries."""
        # Remove all cache files
        for filename in os.listdir(self.cache_dir):
            if filename.endswith('.json') and filename != 'cache_metadata.json':
                try:
                    os.remove(os.path.join(self.cache_dir, filename))
                except IOError as e:
                    logger.warning(f"Failed to remove cache file {filename}: {e}")
        
        # Clear metadata
        self.metadata = {}
        self._save_metadata()
        logger.info("Cleared all cache entries")
    
    def cleanup_expired(self):
        """Remove expired cache entries."""
        keys_to_remove = []
        
        for cache_key in self.metadata.keys():
            if not self._is_cache_valid(cache_key):
                keys_to_remove.append(cache_key)
        
        for key in keys_to_remove:
            self._remove_cache_entry(key)
        
        logger.info(f"Cleaned up {len(keys_to_remove)} expired cache entries")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        total_entries = len(self.metadata)
        total_size = 0
        valid_entries = 0
        expired_entries = 0
        
        for cache_key, entry in self.metadata.items():
            total_size += entry.get('file_size', 0)
            
            if self._is_cache_valid(cache_key):
                valid_entries += 1
            else:
                expired_entries += 1
        
        return {
            'total_entries': total_entries,
            'valid_entries': valid_entries,
            'expired_entries': expired_entries,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'cache_dir': self.cache_dir
        }
    
    def list_cached_queries(self) -> List[Dict[str, Any]]:
        """List all cached queries with their metadata.
        
        Returns:
            List of cached query information
        """
        queries = []
        
        for cache_key, entry in self.metadata.items():
            queries.append({
                'cache_key': cache_key,
                'query': entry.get('query', ''),
                'api_type': entry.get('api_type', ''),
                'created_at': entry.get('created_at', ''),
                'ttl_hours': entry.get('ttl_hours', self.default_ttl_hours),
                'result_count': entry.get('result_count', 0),
                'file_size': entry.get('file_size', 0),
                'is_valid': self._is_cache_valid(cache_key)
            })
        
        return queries
