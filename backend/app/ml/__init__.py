"""Machine learning classification package.

Contains modules for reproducible dataset extraction, cross-validation training,
feature scaling, probability calibration, and model artifact serialization.

NOTE: Real training and artifact generation are scheduled for Phase 2.
No fake model weights or simulated predictions are included here.
"""

from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
