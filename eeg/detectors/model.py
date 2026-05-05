"""EEG - Model Security Detector (endpoints, weights, inference)"""
from EEG.eeg.detectors.base import BaseDetector


class ModelDetector(BaseDetector):
    name = "model"
    category = "model"
