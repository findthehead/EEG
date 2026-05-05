"""EEG - Prompt Injection & AI Logic Vulnerability Detector"""
from EEG.eeg.detectors.base import BaseDetector


class PromptDetector(BaseDetector):
    name = "prompt"
    category = "prompt"
