'''
Training script for model
'''
import os
import numpy as np
import pandas as pd
import lightgbm as lgb
from config import FEATURE_COLS, MODEL_PATH, SEED, IMPORT_DROPOUT_RATE, RAW_COLS_NEEDED