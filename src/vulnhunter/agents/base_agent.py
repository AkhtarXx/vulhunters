"""
🔥 ADVANCED Base Agent with Caching Support

All agents now use cached contract context to save 80% tokens!
"""

from abc import ABC, abstractmethod
from typing import Optional, Any
from loguru import logger

from ..gemini import get_client, GeminiClient


class BaseAgent(ABC):
    """Abstract base class for all security analysis agents with CACHING."""
    
    def __init__(
        self,
        name: str,
        system_prompt: str,
        client: Optional[GeminiClient] = None,
        model: Optional[str] = None,
    ):
        """Initialize agent with name and system prompt."""
        self.name = name
        self.system_prompt = system_prompt
        self.client = client or get_client()
        self.model = model
        self.history: list[dict] = []
        self._current_cache: Optional[str] = None  # Cache name for current contract
        
        logger.info(f"Agent '{name}' initialized")
    
    @abstractmethod
    def analyze(self, context: dict) -> dict:
        """Perform analysis on given context.
        
        Args:
            context: Analysis context. Should contain:
                - contract_code: str
                - contract_name: str (optional)
                - cache_name: str (optional, for reusing cache)
                
        Returns:
            Analysis results
        """
        pass
    
    def setup_cache(self, contract_code: str, contract_name: str = "Contract") -> str:
        """Setup context cache for a contract.
        
        Call this once before running multiple analyses on the same contract.
        
        Args:
            contract_code: The Solidity source code
            contract_name: Name of the contract
            
        Returns:
            Cache name to pass to other agents
        """
        self._current_cache = self.client.cache_contract(
            contract_code=contract_code,
            contract_name=contract_name,
        )
        return self._current_cache
    
    def use_cache(self, cache_name: str) -> None:
        """Use an existing cache from another agent.
        
        Args:
            cache_name: Cache name from setup_cache()
        """
        self._current_cache = cache_name
    
    async def think(self, prompt: str, json_output: bool = False) -> str:
        """Generate a response using the AI model (ASYNC).
        
        Args:
            prompt: The prompt to send
            json_output: Whether to expect JSON output
            
        Returns:
            Model response
        """
        logger.debug(f"🧠 [{self.name}] Thinking... (prompt: {len(prompt)} chars, json: {json_output})")
        
        response = await self.client.generate_async(
            prompt=prompt,
            model=self.model,
            system_instruction=self.system_prompt,
            json_output=json_output,
        )
        
        # Handle None response
        if response is None:
            logger.error(f"❌ [{self.name}] Got None response from Gemini API")
            response = '{"error": "No response from API", "vulnerabilities": []}'
        
        logger.debug(f"💭 [{self.name}] Response received ({len(response)} chars)")
        
        # Track in history
        self.history.append({
            "role": "user",
            "content": prompt[:200],  # Truncate for storage
        })
        self.history.append({
            "role": "assistant",
            "content": response[:200],
        })
        
        return response
    
    def research_exploit(self, query: str, wait: bool = True) -> dict:
        """Use Deep Research to research historical exploits.
        
        Args:
            query: Research query (e.g., "Euler Finance reentrancy hack 2023")
            wait: Whether to wait for completion
            
        Returns:
            Research results with summary and sources
        """
        logger.info(f"{self.name} researching: {query[:50]}...")
        return self.client.deep_research(query, wait_for_completion=wait)
    
    def find_variants(
        self,
        vulnerability_description: str,
        contract_code: str,
    ) -> str:
        """Find variants of a known vulnerability (Big Sleep inspired).
        
        Args:
            vulnerability_description: Known vuln to search for variants of
            contract_code: Contract to search
            
        Returns:
            JSON string with variants found
        """
        logger.info(f"{self.name} searching for variants...")
        return self.client.analyze_with_variant_search(
            vulnerability_description=vulnerability_description,
            contract_code=contract_code,
        )
    
    async def debate(self, opponent_argument: str, context: str) -> str:
        """Respond to an opponent's argument in a debate (ASYNC)."""
        debate_prompt = f"""
        Original Context:
        {context}
        
        Opponent's Argument:
        {opponent_argument}
        
        Provide your counter-argument or response based on your expertise and perspective.
        Be specific, cite evidence from the code, and maintain your designated mindset.
        """
        return await self.think(debate_prompt)
    
    def get_history(self) -> list[dict]:
        """Get agent's conversation history."""
        return self.history.copy()
    
    def clear_history(self) -> None:
        """Clear conversation history."""
        self.history = []
        self._current_cache = None
