import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

print("[*] Generating exact high-resolution replica of your original EDA matrix...")
try:
    # Hardcode the exact mathematical matrix from your original screenshot
    data = {
        "Phishing Label": [1.00, -0.53, 0.36],
        "Dot Count":      [-0.53, 1.00, -0.11],
        "Hyphen Count":   [0.36, -0.11, 1.00]
    }
    
    # Create the DataFrame
    corr_matrix = pd.DataFrame(data, index=["Phishing Label", "Dot Count", "Hyphen Count"])

    # Setup the plot background and sizing
    plt.figure(figsize=(8, 6), facecolor='#161920')
    plt.rcParams['font.sans-serif'] = 'Arial'

    # The exact Red/Blue colormap where Red=Positive and Blue=Negative
    ax = sns.heatmap(corr_matrix, annot=True, fmt=".2f", cmap="RdBu_r", vmin=-1, vmax=1, center=0, 
                square=True, linewidths=.5, linecolor='#161920', 
                cbar_kws={"shrink": .8, "label": "Correlation Coefficient"},
                annot_kws={"size": 15, "weight": "bold", "color": "white"})
    
    # Restoring the sleek Dark Mode UI around the borders
    ax.set_facecolor('#161920')
    ax.tick_params(colors='white', labelsize=12)
    
    # Formatting the colorbar legend on the right so the text is white
    cbar = ax.collections[0].colorbar
    cbar.ax.yaxis.label.set_color('white')
    cbar.ax.yaxis.label.set_size(12)
    cbar.ax.yaxis.set_tick_params(color='white')
    plt.setp(plt.getp(cbar.ax.axes, 'yticklabels'), color='white')

    # The EXACT Title from your screenshot
    plt.title("Insight 2: Structural Anomaly Correlation Matrix", pad=20, fontsize=16, color='white', weight='bold')
    plt.tight_layout()

    print("[*] Saving new mathematical matrix as 'cloned_correlation_matrix.png'...")
    plt.savefig("cloned_correlation_matrix.png", dpi=300, facecolor='#161920', bbox_inches='tight')
    print("[*] Success! Open 'cloned_correlation_matrix.png' to see the exact clone.")
except Exception as e:
    print(f"[!] Error: {e}")
