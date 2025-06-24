from abc import ABC, abstractmethod
from src.memory.semantic.state import State

class Agent(ABC):
    def __init__(self, **kwargs):
        pass

    @abstractmethod
    def run(self):
        raise NotImplementedError

    @abstractmethod
    def get_agent_state(self) -> State:
        raise NotImplementedError
