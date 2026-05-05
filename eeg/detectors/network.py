"""EEG - Network Exposure Detector"""
from EEG.eeg.detectors.base import BaseDetector


class NetworkDetector(BaseDetector):
    name = "network"
    category = "network"
