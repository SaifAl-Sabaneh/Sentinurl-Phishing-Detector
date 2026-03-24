import pandas as pd
try:
    df = pd.read_csv('stress_test_results.csv')
    missed = df[df['Classification'] == 'Safe'].tail(149)
    missed.to_csv('missed_analysis_v4.csv', index=False)
    print(f"Successfully extracted {len(missed)} URLs to missed_analysis_v4.csv")
except Exception as e:
    print(f"Error: {e}")
