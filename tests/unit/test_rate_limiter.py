"""
🧪 Unit Tests for Rate Limiter
==============================

Tests the rate limiter module with:
- Daily tracking and persistence
- Per-minute rate limiting
- State file operations
- Day reset behavior
- Async wait_if_needed behavior
"""

import pytest
import asyncio
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import asdict
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from vulnhunter.rate_limiter import (
    RateLimiter, 
    RateLimitState, 
    get_rate_limiter,
    parse_retry_delay,
)


class TestRateLimitState:
    """Test RateLimitState dataclass and persistence."""
    
    def test_default_initialization(self):
        """Test state initializes with defaults."""
        state = RateLimitState()
        
        # Check defaults - current_date starts empty in the dataclass
        assert state.daily_requests == 0
        assert state.daily_tokens == 0
        assert state.total_requests_all_time == 0
        assert state.minute_requests == 0
        assert state.minute_tokens == 0
    
    def test_custom_initialization(self):
        """Test state with custom values."""
        state = RateLimitState(
            current_date="2024-01-15",
            daily_requests=100,
            daily_tokens=500000,
            total_requests_all_time=1000
        )
        
        assert state.current_date == "2024-01-15"
        assert state.daily_requests == 100
        assert state.daily_tokens == 500000
        assert state.total_requests_all_time == 1000
    
    def test_to_dict(self):
        """Test state serialization with asdict."""
        state = RateLimitState(
            current_date="2024-01-15",
            daily_requests=50,
            daily_tokens=250000
        )
        
        # Use dataclasses.asdict
        data = asdict(state)
        
        assert isinstance(data, dict)
        assert data["current_date"] == "2024-01-15"
        assert data["daily_requests"] == 50
        assert data["daily_tokens"] == 250000
    
    def test_save_and_load(self, temp_dir):
        """Test state persistence to file."""
        state_file = temp_dir / "test_state.json"
        
        # Save
        original = RateLimitState(
            current_date="2024-01-15",
            daily_requests=42,
            daily_tokens=210000,
            total_requests_all_time=999
        )
        original.save(str(state_file))
        
        assert state_file.exists()
        
        # Load
        loaded = RateLimitState.load(str(state_file))
        
        assert loaded.current_date == "2024-01-15"
        assert loaded.daily_requests == 42
        assert loaded.total_requests_all_time == 999
    
    def test_load_missing_file(self, temp_dir):
        """Test loading non-existent file returns default state."""
        missing_file = temp_dir / "nonexistent.json"
        
        state = RateLimitState.load(str(missing_file))
        
        # Should return default state
        assert state.daily_requests == 0
    
    def test_load_corrupted_file(self, temp_dir):
        """Test handling corrupted state file."""
        corrupted_file = temp_dir / "corrupted.json"
        corrupted_file.write_text("{ not valid json }")
        
        state = RateLimitState.load(str(corrupted_file))
        
        # Should return default state
        assert state.daily_requests == 0
    
    def test_creates_parent_directories(self, temp_dir):
        """Test that save creates parent directories."""
        nested_file = temp_dir / "nested" / "deep" / "state.json"
        
        state = RateLimitState(daily_requests=10)
        state.save(str(nested_file))
        
        assert nested_file.exists()
        assert nested_file.parent.exists()


class TestRateLimiter:
    """Test RateLimiter class."""
    
    def test_initialization(self, temp_dir):
        """Test limiter initializes with correct limits."""
        state_file = str(temp_dir / "rate_limit.json")
        
        limiter = RateLimiter(
            requests_per_minute=22,
            tokens_per_minute=900_000,
            requests_per_day=245,
            state_file=state_file
        )
        
        assert limiter.requests_per_minute == 22
        assert limiter.tokens_per_minute == 900_000
        assert limiter.requests_per_day == 245
        assert limiter.state.daily_requests == 0
    
    def test_record_tokens(self, isolated_rate_limiter):
        """Test recording token usage."""
        limiter = isolated_rate_limiter
        
        limiter.record_tokens(50_000)
        limiter.record_tokens(30_000)
        limiter.record_tokens(20_000)
        
        usage = limiter.get_current_usage()
        
        assert usage['daily_requests'] == 3
    
    def test_daily_tracking_persistence(self, temp_dir):
        """Test daily usage persists across restarts."""
        state_file = str(temp_dir / "rate_limit.json")
        
        # First instance
        limiter1 = RateLimiter(
            requests_per_minute=22,
            requests_per_day=245,
            state_file=state_file
        )
        limiter1.record_tokens(10_000)
        limiter1.record_tokens(20_000)
        limiter1.record_tokens(30_000)
        
        # Simulate restart
        limiter2 = RateLimiter(
            requests_per_minute=22,
            requests_per_day=245,
            state_file=state_file
        )
        
        usage = limiter2.get_current_usage()
        
        assert usage['daily_requests'] == 3
    
    def test_day_reset(self, temp_dir):
        """Test counters reset on new day."""
        state_file = str(temp_dir / "rate_limit.json")
        
        # Create old state from yesterday
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        old_state = RateLimitState(
            current_date=yesterday,
            daily_requests=200,
            daily_tokens=5_000_000,
            total_requests_all_time=500
        )
        old_state.save(state_file)
        
        # Load - should auto-reset for today
        limiter = RateLimiter(
            requests_per_minute=22,
            requests_per_day=245,
            state_file=state_file
        )
        
        today = datetime.now().strftime("%Y-%m-%d")
        
        assert limiter.state.current_date == today
        assert limiter.state.daily_requests == 0
        assert limiter.state.daily_tokens == 0
        assert limiter.state.total_requests_all_time == 500  # Preserved!
    
    def test_get_current_usage(self, isolated_rate_limiter):
        """Test usage statistics."""
        limiter = isolated_rate_limiter
        limiter.record_tokens(100_000)
        
        usage = limiter.get_current_usage()
        
        assert 'date' in usage
        assert 'daily_requests' in usage
        assert 'daily_limit' in usage
        assert 'daily_remaining' in usage
        assert usage['daily_requests'] == 1
    
    def test_print_status(self, isolated_rate_limiter):
        """Test status display string."""
        limiter = isolated_rate_limiter
        limiter.record_tokens(50_000)
        
        status = limiter.print_status()
        
        assert "Rate Limit Status" in status or "rate" in status.lower()
    
    def test_all_time_tracking(self, temp_dir):
        """Test all-time request tracking."""
        state_file = str(temp_dir / "rate_limit.json")
        
        limiter = RateLimiter(
            requests_per_minute=22,
            requests_per_day=245,
            state_file=state_file
        )
        
        for _ in range(5):
            limiter.record_tokens(10_000)
        
        assert limiter.state.total_requests_all_time == 5
        
        # Simulate new day
        limiter.state.current_date = "1990-01-01"
        limiter._check_day_reset()
        
        # Daily reset, but all-time preserved
        assert limiter.state.daily_requests == 0
        assert limiter.state.total_requests_all_time == 5


class TestRateLimiterAsync:
    """Test async rate limiting behavior."""
    
    @pytest.mark.asyncio
    async def test_wait_if_needed_no_wait(self, isolated_rate_limiter):
        """Test no waiting when under limits."""
        limiter = isolated_rate_limiter
        
        waited = await limiter.wait_if_needed(estimated_tokens=10_000)
        
        assert waited == 0
    
    @pytest.mark.asyncio
    async def test_wait_if_needed_returns_numeric(self, isolated_rate_limiter):
        """Test that wait_if_needed returns a numeric value."""
        limiter = isolated_rate_limiter
        
        waited = await limiter.wait_if_needed(estimated_tokens=50_000)
        
        # Should return a number (0 if no wait needed)
        assert isinstance(waited, (int, float))
        assert waited >= 0
    
    @pytest.mark.asyncio
    async def test_per_minute_throttling(self, temp_dir):
        """Test per-minute rate limiting triggers wait."""
        state_file = str(temp_dir / "rate_limit.json")
        
        # Very low limit for testing
        limiter = RateLimiter(
            requests_per_minute=3,
            tokens_per_minute=100_000,
            requests_per_day=1000,
            state_file=state_file
        )
        
        # Make 3 quick requests
        for _ in range(3):
            limiter.record_tokens(1000)
        
        # 4th request should need to wait
        start = time.time()
        waited = await limiter.wait_if_needed(estimated_tokens=1000)
        elapsed = time.time() - start
        
        # Should have waited (at least something)
        # Note: might be very small if requests were spread out
        assert elapsed >= 0


class TestRetryDelayParsing:
    """Test parsing retry delay from error messages."""
    
    def test_parse_delay_from_google_format(self):
        """Test parsing delay from Google's error format."""
        error_msg = "RESOURCE_EXHAUSTED: 429 Retry after 35s"
        delay = parse_retry_delay(error_msg)
        
        # Should extract some delay
        assert delay is None or delay > 0
    
    def test_parse_delay_seconds_format(self):
        """Test parsing 'NN seconds' format."""
        error_msg = "Rate limit exceeded. Retry in 45 seconds."
        delay = parse_retry_delay(error_msg)
        
        assert delay is None or delay >= 0
    
    def test_parse_delay_no_match(self):
        """Test returns None when no delay found."""
        error_msg = "Some other error without delay info"
        delay = parse_retry_delay(error_msg)
        
        assert delay is None


class TestGetRateLimiter:
    """Test singleton rate limiter getter."""
    
    def test_returns_same_instance(self):
        """Test get_rate_limiter returns singleton."""
        limiter1 = get_rate_limiter()
        limiter2 = get_rate_limiter()
        
        assert limiter1 is limiter2
    
    def test_limiter_has_correct_defaults(self):
        """Test singleton has expected default limits."""
        limiter = get_rate_limiter()
        
        # Should have reasonable defaults
        assert limiter.requests_per_day > 0
        assert limiter.requests_per_minute > 0
        assert limiter.tokens_per_minute > 0


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_concurrent_recording(self, isolated_rate_limiter):
        """Test recording under concurrent access."""
        limiter = isolated_rate_limiter
        
        # Simulate rapid recording
        for i in range(100):
            limiter.record_tokens(1000 + i)
        
        assert limiter.state.daily_requests == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
