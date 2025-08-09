"""Caching utilities for OpenShift AI Security Dashboard."""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional, Callable
from functools import wraps
from datetime import datetime, timedelta

from ..config import config

logger = logging.getLogger(__name__)


class SimpleCache:
    """Simple file-based cache with TTL support."""
    
    def __init__(self, cache_dir: Optional[Path] = None, default_ttl: int = None):
        self.cache_dir = cache_dir or Path(".cache")
        self.cache_dir.mkdir(exist_ok=True)
        self.default_ttl = default_ttl or config.CACHE_TTL
        self.memory_cache = {}
    
    def _get_cache_file(self, key: str) -> Path:
        """Get cache file path for a key."""
        # Simple key sanitization
        safe_key = "".join(c for c in key if c.isalnum() or c in "-_.")
        return self.cache_dir / f"{safe_key}.cache"
    
    def _is_expired(self, timestamp: float, ttl: int) -> bool:
        """Check if cache entry is expired."""
        return time.time() - timestamp > ttl
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        if not config.ENABLE_CACHING:
            return default
        
        # Check memory cache first
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            if not self._is_expired(entry["timestamp"], entry["ttl"]):
                logger.debug(f"Cache hit (memory): {key}")
                return entry["value"]
            else:
                del self.memory_cache[key]
        
        # Check file cache
        cache_file = self._get_cache_file(key)
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    entry = json.load(f)
                
                if not self._is_expired(entry["timestamp"], entry["ttl"]):
                    # Store in memory cache for faster access
                    self.memory_cache[key] = entry
                    logger.debug(f"Cache hit (file): {key}")
                    return entry["value"]
                else:
                    cache_file.unlink()
                    logger.debug(f"Cache expired: {key}")
            
            except (json.JSONDecodeError, KeyError, OSError) as e:
                logger.warning(f"Cache read error for {key}: {e}")
                cache_file.unlink(missing_ok=True)
        
        logger.debug(f"Cache miss: {key}")
        return default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache."""
        if not config.ENABLE_CACHING:
            return
        
        ttl = ttl or self.default_ttl
        timestamp = time.time()
        
        entry = {
            "value": value,
            "timestamp": timestamp,
            "ttl": ttl
        }
        
        # Store in memory cache
        self.memory_cache[key] = entry
        
        # Store in file cache
        cache_file = self._get_cache_file(key)
        try:
            with open(cache_file, 'w') as f:
                json.dump(entry, f, default=str)
            logger.debug(f"Cache set: {key}")
        except (OSError, TypeError) as e:
            logger.warning(f"Cache write error for {key}: {e}")
    
    def delete(self, key: str) -> None:
        """Delete value from cache."""
        # Remove from memory cache
        self.memory_cache.pop(key, None)
        
        # Remove from file cache
        cache_file = self._get_cache_file(key)
        cache_file.unlink(missing_ok=True)
        logger.debug(f"Cache deleted: {key}")
    
    def clear(self) -> None:
        """Clear all cache."""
        self.memory_cache.clear()
        
        for cache_file in self.cache_dir.glob("*.cache"):
            cache_file.unlink(missing_ok=True)
        
        logger.debug("Cache cleared")
    
    def cleanup_expired(self) -> int:
        """Clean up expired cache entries."""
        cleaned_count = 0
        
        # Clean memory cache
        expired_keys = []
        for key, entry in self.memory_cache.items():
            if self._is_expired(entry["timestamp"], entry["ttl"]):
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.memory_cache[key]
            cleaned_count += 1
        
        # Clean file cache
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                with open(cache_file, 'r') as f:
                    entry = json.load(f)
                
                if self._is_expired(entry["timestamp"], entry["ttl"]):
                    cache_file.unlink()
                    cleaned_count += 1
            
            except (json.JSONDecodeError, KeyError, OSError):
                cache_file.unlink(missing_ok=True)
                cleaned_count += 1
        
        logger.debug(f"Cleaned {cleaned_count} expired cache entries")
        return cleaned_count


# Global cache instance
cache = SimpleCache()


def cached(ttl: Optional[int] = None, key_func: Optional[Callable] = None):
    """Decorator for caching function results."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not config.ENABLE_CACHING:
                return func(*args, **kwargs)
            
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Simple key generation
                key_parts = [func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = "_".join(key_parts)
            
            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result
        
        return wrapper
    return decorator


def cache_api_response(api_name: str, endpoint: str, params: Dict[str, Any] = None) -> str:
    """Generate cache key for API responses."""
    key_parts = [api_name, endpoint]
    if params:
        # Sort parameters for consistent keys
        param_str = "_".join(f"{k}={v}" for k, v in sorted(params.items()) if v is not None)
        key_parts.append(param_str)
    return "_".join(key_parts)


def cache_database_query(table: str, filters: Dict[str, Any] = None) -> str:
    """Generate cache key for database queries."""
    key_parts = ["db", table]
    if filters:
        filter_str = "_".join(f"{k}={v}" for k, v in sorted(filters.items()) if v is not None)
        key_parts.append(filter_str)
    return "_".join(key_parts)


class RateLimitCache:
    """Cache for managing API rate limits."""
    
    def __init__(self):
        self.requests = {}
    
    def can_make_request(self, api_key: str, max_requests: int, window_seconds: int) -> bool:
        """Check if request can be made within rate limit."""
        now = datetime.now()
        window_start = now - timedelta(seconds=window_seconds)
        
        if api_key not in self.requests:
            self.requests[api_key] = []
        
        # Clean old requests
        self.requests[api_key] = [
            req_time for req_time in self.requests[api_key] 
            if req_time > window_start
        ]
        
        # Check rate limit
        if len(self.requests[api_key]) >= max_requests:
            return False
        
        # Record this request
        self.requests[api_key].append(now)
        return True
    
    def get_reset_time(self, api_key: str, window_seconds: int) -> Optional[datetime]:
        """Get when rate limit will reset."""
        if api_key not in self.requests or not self.requests[api_key]:
            return None
        
        oldest_request = min(self.requests[api_key])
        return oldest_request + timedelta(seconds=window_seconds)


# Global rate limit cache
rate_limit_cache = RateLimitCache()