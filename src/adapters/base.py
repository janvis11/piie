from __future__ import annotations
from abc import ABC, abstractmethod
from contracts.models import AppOutput
from dataset.schema import TestCase


class BaseAdapter(ABC):
    """
    Abstract interface for any GenAI system adapter.

    An adapter connects the evaluation harness to a system under test
    such as LangGraph, LangChain, a custom API, or any GenAI workflow.
    """

    @abstractmethod
    def run(self, case: TestCase) -> AppOutput:
        """
        Execute a single evaluation test case against the target system.

        Args:
            case: A validated test case from the evaluation dataset.

        Returns:
            AppOutput: Standardized output produced by the system under test.
        """
        raise NotImplementedError("Adapters must implement the run() method.")