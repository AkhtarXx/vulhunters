"""
🚦 Rate Limiter for Gemini API with AUTO-RECOVERY

Implements:
1. Token bucket rate limiting (per-minute tracking)
2. Daily request limit (250/day) with AUTO-SLEEP until next day
3. Automatic retry with exponential backoff on 429 errors
4. Persistent state - survives restarts
5. Perfect for unattended cloud deployment

Based on Google AI documentation:
- Rate limits: https://ai.google.dev/gemini-api/docs/rate-limits

YOUR LIMITS:
- 25 requests per minute
- 1M tokens per minute
- 250 requests per day (HARD LIMIT - sleeps until midnight!)
"""

import asyncio
import time
import re
import json
from functools import wraps
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional, Callable, Any
from threading import Lock
from loguru import logger

from .config import settings


# =============================================================================
# PERSISTENT STATE FOR DAILY TRACKING
# =============================================================================

@dataclass
class RateLimitState:
    """Persistent state for rate limiting - survives restarts."""
    # Daily tracking
    current_date: str = ""  # YYYY-MM-DD
    daily_requests: int = 0
    daily_tokens: int = 0
    
    # Minute tracking (not persisted, just for runtime)
    minute_window_start: float = 0.0
    minute_requests: int = 0
    minute_tokens: int = 0
    
    # Statistics
    total_requests_all_time: int = 0
    total_tokens_all_time: int = 0
    total_daily_waits: int = 0
    total_wait_time_hours: float = 0.0
    
    # Last run info
    last_request_time: str = ""
    
    @classmethod
    def load(cls, state_file: str) -> "RateLimitState":
        """Load state from file."""
        path = Path(state_file)
        if path.exists():
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                # Filter only known fields
                known_fields = {f.name for f in cls.__dataclass_fields__.values()}
                filtered_data = {k: v for k, v in data.items() if k in known_fields}
                return cls(**filtered_data)
            except Exception as e:
                logger.warning(f"Failed to load rate limit state: {e}")
        return cls()
    
    def save(self, state_file: str):
        """Save state to file."""
        path = Path(state_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(asdict(self), f, indent=2)


# =============================================================================
# MAIN RATE LIMITER CLASS
# =============================================================================

class RateLimiter:
    """Token bucket rate limiter for Gemini API with DAILY LIMIT support.
    
    YOUR Gemini API limits:
    - 25 requests per minute
    - 1,000,000 tokens per minute
    - 250 requests per day (THIS IS THE HARD LIMIT!)
    
    When daily limit is hit:
    - Automatically sleeps until midnight
    - Auto-resumes when new day starts
    - Perfect for unattended cloud runs
    """
    
    # YOUR LIMITS
    REQUESTS_PER_MINUTE = 25
    TOKENS_PER_MINUTE = 1_000_000
    REQUESTS_PER_DAY = 250
    
    # Safety margins (90% of limits)
    SAFE_REQUESTS_PER_MINUTE = 22
    SAFE_TOKENS_PER_MINUTE = 900_000
    SAFE_REQUESTS_PER_DAY = 245  # Leave buffer
    
    def __init__(
        self,
        tokens_per_minute: Optional[int] = None,
        requests_per_minute: Optional[int] = None,
        requests_per_day: Optional[int] = None,
        state_file: str = ".vulnhunter_state/rate_limit.json",
        on_daily_limit: Optional[Callable] = None,
        on_resume: Optional[Callable] = None,
    ):
        """
        Initialize rate limiter.
        
        Args:
            tokens_per_minute: Override token limit
            requests_per_minute: Override RPM limit
            requests_per_day: Override daily limit
            state_file: Path to persist state
            on_daily_limit: Callback when daily limit hit
            on_resume: Callback when resuming after wait
        """
        self.tokens_per_minute = tokens_per_minute or self.SAFE_TOKENS_PER_MINUTE
        self.requests_per_minute = requests_per_minute or self.SAFE_REQUESTS_PER_MINUTE
        self.requests_per_day = requests_per_day or self.SAFE_REQUESTS_PER_DAY
        
        self.state_file = state_file
        self.state = RateLimitState.load(state_file)
        self._lock = Lock()
        self._async_lock = asyncio.Lock()
        self.on_daily_limit = on_daily_limit
        self.on_resume = on_resume
        
        # Per-minute tracking (in-memory, resets on restart)
        self._token_usage: list[tuple[float, int]] = []  # (timestamp, tokens)
        self._request_times: list[float] = []
        
        # Check if we need to reset for new day
        self._check_day_reset()
        
        remaining = self.requests_per_day - self.state.daily_requests
        logger.info(f"🚦 Rate limiter initialized")
        logger.info(f"   Daily: {self.state.daily_requests}/{self.requests_per_day} ({remaining} remaining)")
        logger.info(f"   Per-minute: {self.requests_per_minute} RPM, {self.tokens_per_minute:,} TPM")
        
        if remaining <= 50:
            logger.warning(f"   ⚠️ Low daily quota! Only {remaining} requests left today.")
    
    def _check_day_reset(self):
        """Reset daily counters if it's a new day."""
        today = datetime.now().strftime("%Y-%m-%d")
        if self.state.current_date != today:
            if self.state.current_date:  # Not first run
                logger.info(f"📅 New day! Resetting daily counters.")
                logger.info(f"   Previous: {self.state.current_date} used {self.state.daily_requests} requests")
            self.state.current_date = today
            self.state.daily_requests = 0
            self.state.daily_tokens = 0
            self.state.save(self.state_file)
        
    def _cleanup_old_entries(self, current_time: float):
        """Remove entries older than 1 minute."""
        cutoff = current_time - 60.0
        self._token_usage = [(t, tokens) for t, tokens in self._token_usage if t > cutoff]
        self._request_times = [t for t in self._request_times if t > cutoff]
    
    def _seconds_until_next_day(self) -> float:
        """Calculate seconds until midnight."""
        now = datetime.now()
        tomorrow = (now + timedelta(days=1)).replace(
            hour=0, minute=0, second=10, microsecond=0
        )
        return (tomorrow - now).total_seconds()
    
    def get_current_usage(self) -> dict:
        """Get current usage statistics."""
        self._check_day_reset()
        now = time.time()
        self._cleanup_old_entries(now)
        
        minute_tokens = sum(tokens for _, tokens in self._token_usage)
        minute_requests = len(self._request_times)
        
        return {
            "date": self.state.current_date,
            "daily_requests": self.state.daily_requests,
            "daily_limit": self.requests_per_day,
            "daily_remaining": self.requests_per_day - self.state.daily_requests,
            "minute_requests": minute_requests,
            "minute_tokens": minute_tokens,
            "total_all_time": self.state.total_requests_all_time,
            "total_daily_waits": self.state.total_daily_waits,
        }
    
    def print_status(self) -> str:
        """Print formatted status to console and return as string."""
        usage = self.get_current_usage()
        
        # Calculate bar
        daily_pct = (usage['daily_requests'] / usage['daily_limit']) * 100
        bar_filled = int(daily_pct / 5)  # 20 chars total
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        
        status = f"""
┌─────────────── Rate Limit Status ───────────────┐
│ Date: {usage['date']}                                 │
│                                                 │
│ Daily:    [{bar}] {daily_pct:.0f}%           │
│           {usage['daily_requests']}/{usage['daily_limit']} requests ({usage['daily_remaining']} remaining)
│                                                 │
│ Per-min:  {usage['minute_requests']}/25 RPM | {usage['minute_tokens']:,}/1M TPM     │
│                                                 │
│ All-time: {usage['total_all_time']} total requests              │
│ Waits:    {usage['total_daily_waits']} daily limit waits                │
└─────────────────────────────────────────────────┘"""
        
        logger.info(status)
        return status
    
    async def wait_if_needed(self, estimated_tokens: int = 50_000) -> float:
        """Wait if rate limit would be exceeded.
        
        IMPORTANT: This will sleep until NEXT DAY if daily limit is hit!
        
        Args:
            estimated_tokens: Estimated tokens for this request
            
        Returns:
            Seconds waited (0 if no wait needed)
        """
        async with self._async_lock:
            with self._lock:
                self._check_day_reset()
                
                now = time.time()
                self._cleanup_old_entries(now)
                
                total_tokens = sum(tokens for _, tokens in self._token_usage)
                total_requests = len(self._request_times)
                
                wait_time = 0.0
                
                # ============================================
                # CHECK DAILY LIMIT (MOST IMPORTANT!)
                # ============================================
                if self.state.daily_requests >= self.requests_per_day:
                    # DAILY LIMIT HIT - Sleep until next day!
                    wait_seconds = self._seconds_until_next_day()
                    await self._sleep_until_next_day(wait_seconds)
                    return wait_seconds
                
                # ============================================
                # CHECK MINUTE TOKEN LIMIT
                # ============================================
                if total_tokens + estimated_tokens > self.tokens_per_minute:
                    if self._token_usage:
                        oldest_time = min(t for t, _ in self._token_usage)
                        wait_time = max(wait_time, (oldest_time + 60.0) - now + 1.0)
                        logger.warning(
                            f"⏳ Token limit approaching ({total_tokens:,}/{self.tokens_per_minute:,}). "
                            f"Waiting {wait_time:.1f}s..."
                        )
                
                # ============================================
                # CHECK MINUTE REQUEST LIMIT
                # ============================================
                if total_requests >= self.requests_per_minute:
                    if self._request_times:
                        oldest_time = min(self._request_times)
                        wait_time = max(wait_time, (oldest_time + 60.0) - now + 1.0)
                        logger.warning(
                            f"⏳ RPM limit reached ({total_requests}/{self.requests_per_minute}). "
                            f"Waiting {wait_time:.1f}s..."
                        )
                
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                    now = time.time()
                    self._cleanup_old_entries(now)
                
                # Record this request
                self._token_usage.append((now, estimated_tokens))
                self._request_times.append(now)
                
                return wait_time
    
    async def _sleep_until_next_day(self, wait_seconds: float):
        """Sleep until next day when daily limit is hit."""
        wait_hours = wait_seconds / 3600
        resume_time = datetime.now() + timedelta(seconds=wait_seconds)
        
        logger.warning("")
        logger.warning("=" * 70)
        logger.warning("🛑 DAILY RATE LIMIT REACHED!")
        logger.warning("=" * 70)
        logger.warning(f"   Requests today: {self.state.daily_requests}/{self.REQUESTS_PER_DAY}")
        logger.warning(f"   Waiting until: {resume_time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.warning(f"   Wait time: {wait_hours:.1f} hours ({wait_seconds:.0f} seconds)")
        logger.warning("")
        logger.warning("   💤 Agent will AUTO-RESUME when new day starts!")
        logger.warning("   📱 You can leave this running on cloud.")
        logger.warning("=" * 70)
        
        # Callback
        if self.on_daily_limit:
            self.on_daily_limit(wait_seconds)
        
        # Update stats
        self.state.total_daily_waits += 1
        self.state.total_wait_time_hours += wait_hours
        self.state.save(self.state_file)
        
        # Sleep in chunks (check every 5 minutes)
        remaining = wait_seconds
        while remaining > 0:
            sleep_chunk = min(remaining, 300)  # 5 minutes
            hours_left = remaining / 3600
            logger.info(f"   💤 Sleeping... {hours_left:.1f} hours remaining")
            await asyncio.sleep(sleep_chunk)
            remaining -= sleep_chunk
            
            # Check if day changed
            today = datetime.now().strftime("%Y-%m-%d")
            if self.state.current_date != today:
                break
        
        # New day!
        logger.info("")
        logger.info("=" * 70)
        logger.info("🌅 NEW DAY! Resuming analysis...")
        logger.info("=" * 70)
        
        # Reset counters
        self._check_day_reset()
        
        # Callback
        if self.on_resume:
            self.on_resume()
    
    def record_tokens(self, actual_tokens: int):
        """Update token count with actual usage (call after response)."""
        with self._lock:
            now = time.time()
            
            # Update minute tracking
            if self._token_usage:
                self._token_usage[-1] = (now, actual_tokens)
            
            # Update daily tracking
            self.state.daily_requests += 1
            self.state.daily_tokens += actual_tokens
            self.state.total_requests_all_time += 1
            self.state.total_tokens_all_time += actual_tokens
            self.state.last_request_time = datetime.now().isoformat()
            self.state.save(self.state_file)
            
            # Log progress
            remaining = self.requests_per_day - self.state.daily_requests
            if remaining <= 20:
                logger.warning(f"   ⚠️ Daily: {self.state.daily_requests}/{self.requests_per_day} ({remaining} left!)")
            elif self.state.daily_requests % 25 == 0:
                logger.info(f"   📊 Daily: {self.state.daily_requests}/{self.requests_per_day} ({remaining} remaining)")
    
    def reset_daily(self):
        """Manually reset daily counters (for testing)."""
        with self._lock:
            self.state.daily_requests = 0
            self.state.daily_tokens = 0
            self.state.current_date = datetime.now().strftime("%Y-%m-%d")
            self.state.save(self.state_file)
            logger.info("🔄 Daily counters reset manually")


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get or create global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def reset_rate_limiter():
    """Reset the global rate limiter (for testing)."""
    global _rate_limiter
    _rate_limiter = None


def parse_retry_delay(error_message: str) -> Optional[float]:
    """Extract retry delay from Google API error message.
    
    Example error: "Please retry in 46.974185599s."
    """
    # Pattern: "retry in Xs" or "retryDelay: 'Xs'"
    patterns = [
        r'retry in (\d+(?:\.\d+)?)s',
        r"retryDelay['\"]?\s*:\s*['\"]?(\d+)s",
    ]
    
    for pattern in patterns:
        match = re.search(pattern, str(error_message), re.IGNORECASE)
        if match:
            return float(match.group(1))
    
    return None


async def retry_on_rate_limit(
    func: Callable,
    *args,
    max_retries: int = 5,
    base_delay: float = 5.0,
    max_delay: float = 120.0,
    **kwargs
) -> Any:
    """Execute function with automatic retry on rate limit errors.
    
    Uses exponential backoff with jitter, respecting Google's retry-after hints.
    
    Args:
        func: Async function to call
        max_retries: Maximum retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay cap
        *args, **kwargs: Arguments for func
        
    Returns:
        Function result
        
    Raises:
        Last exception if all retries exhausted
    """
    import random
    
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            # Wait if approaching rate limit
            rate_limiter = get_rate_limiter()
            await rate_limiter.wait_if_needed()
            
            # Execute the function
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return await asyncio.to_thread(func, *args, **kwargs)
                
        except Exception as e:
            error_str = str(e)
            last_exception = e
            
            # Check if it's a rate limit error (429)
            is_rate_limit = any(x in error_str for x in [
                "429",
                "RESOURCE_EXHAUSTED",
                "rate limit",
                "quota exceeded",
                "Too Many Requests",
            ])
            
            if not is_rate_limit:
                # Not a rate limit error - re-raise immediately
                raise
            
            if attempt >= max_retries:
                logger.error(f"❌ Rate limit: All {max_retries} retries exhausted")
                raise
            
            # Calculate delay
            # First check if Google told us exactly how long to wait
            google_delay = parse_retry_delay(error_str)
            
            if google_delay:
                delay = google_delay + 2.0  # Add buffer
                logger.warning(
                    f"⏳ Rate limit hit (attempt {attempt + 1}/{max_retries + 1}). "
                    f"Google says wait {google_delay:.1f}s, waiting {delay:.1f}s..."
                )
            else:
                # Exponential backoff with jitter
                delay = min(base_delay * (2 ** attempt) + random.uniform(0, 1), max_delay)
                logger.warning(
                    f"⏳ Rate limit hit (attempt {attempt + 1}/{max_retries + 1}). "
                    f"Retrying in {delay:.1f}s..."
                )
            
            await asyncio.sleep(delay)
    
    raise last_exception


def with_retry(max_retries: int = 5, base_delay: float = 5.0):
    """Decorator to add retry logic to async functions.
    
    Usage:
        @with_retry(max_retries=3)
        async def my_api_call():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await retry_on_rate_limit(
                func, *args,
                max_retries=max_retries,
                base_delay=base_delay,
                **kwargs
            )
        return wrapper
    return decorator


class ConcurrencyLimiter:
    """Limit concurrent API calls to avoid overwhelming the API."""
    
    def __init__(self, max_concurrent: Optional[int] = None):
        self.max_concurrent = max_concurrent or settings.max_concurrent_contracts
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        logger.info(f"🚦 Concurrency limiter: max {self.max_concurrent} concurrent")
        
    async def __aenter__(self):
        await self.semaphore.acquire()
        return self
        
    async def __aexit__(self, *args):
        self.semaphore.release()


# Global concurrency limiter
_concurrency_limiter: Optional[ConcurrencyLimiter] = None


def get_concurrency_limiter(max_concurrent: int = 3) -> ConcurrencyLimiter:
    """Get or create global concurrency limiter."""
    global _concurrency_limiter
    if _concurrency_limiter is None:
        _concurrency_limiter = ConcurrencyLimiter(max_concurrent)
    return _concurrency_limiter
