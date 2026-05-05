"""EEG - Secrets & Credential Exposure Detector"""
from EEG.eeg.detectors.base import BaseDetector


class SecretsDetector(BaseDetector):
    name = "secrets"
    category = "secrets"
