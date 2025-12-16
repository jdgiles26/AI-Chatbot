"""
Mac Mini M2 Security Assistant
A comprehensive security monitoring and analysis tool optimized for Mac Mini M2.
"""

__version__ = '1.0.0'
__author__ = 'AI Chatbot Security Team'

from .scanner import FileSystemScanner
from .security_analyzer import SecurityAnalyzer
from .reporter import SecurityReporter

__all__ = [
    'FileSystemScanner',
    'SecurityAnalyzer',
    'SecurityReporter'
]
