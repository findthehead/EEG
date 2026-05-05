"""EEG - Infrastructure as Code Detector (Terraform, Bicep, CloudFormation)"""
from EEG.eeg.detectors.base import BaseDetector


class IaCDetector(BaseDetector):
    name = "iac"
    category = "iac"
