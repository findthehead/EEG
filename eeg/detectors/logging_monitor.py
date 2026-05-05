"""EEG - Logging & Monitoring Detector"""
from EEG.eeg.detectors.base import BaseDetector


class LoggingDetector(BaseDetector):
    name = "logging"
    category = "logging"
