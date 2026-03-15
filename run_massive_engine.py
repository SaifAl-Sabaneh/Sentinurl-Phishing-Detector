
import sys
import time
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.append('.')
from sentinurl import predict_ultimate

def fast_predict(url):
    try:
        # Pass pure_ml_override to true if we had it, but predict_ultimate is fast enough 
        # actually, sentinurl actively checks APIs. We MUST bypass APIs for 200k.
        pass
    except:
        pass
