"""EEG - Policy Misconfiguration Detector"""
from EEG.eeg.detectors.base import BaseDetector


class PolicyDetector(BaseDetector):
    name = "policy"
    category = "policy"
