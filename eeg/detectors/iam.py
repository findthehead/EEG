"""EEG - IAM Misconfiguration Detector"""
from EEG.eeg.detectors.base import BaseDetector


class IAMDetector(BaseDetector):
    name = "iam"
    category = "iam"
