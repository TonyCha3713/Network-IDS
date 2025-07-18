import matplotlib.pyplot as plt
import pandas as pd
import time
import numpy as np

plt.style.use('seaborn-v0_8-darkgrid')  # modern, clean style
plt.ion()  # turn on interactive mode

fig, (ax_bar, ax_pie) = plt.subplots(2, 1, figsize=(10, 8), gridspec_kw={'height_ratios': [2, 1]})
plt.tight_layout(pad=4.0)

while True:
    try:
        # Read the alerts CSV (real-time alerts)
        df = pd.read_csv("ids_alerts.csv")
        if df.empty or 'Label' not in df.columns:
            raise ValueError("No alert data or missing 'Label' column in ids_alerts.csv")
        now = pd.Timestamp.now()

        # Count each attack type
        counts = df["Label"].value_counts().sort_index()
        attack_types = counts.index.tolist()
        values = counts.values

        # --- Bar Chart ---
        ax_bar.clear()
        cmap = plt.get_cmap('tab10')
        colors = list(cmap(range(10)))  # up to 10 distinct colors
        color_map = {atk: colors[i % len(colors)] for i, atk in enumerate(attack_types)}
        bars = ax_bar.bar(attack_types, values, color=[color_map[a] for a in attack_types])
        ax_bar.set_title("Real-Time IDS Alerts", fontsize=16, fontweight='bold')
        ax_bar.set_xlabel("Attack Type", fontsize=12)
        ax_bar.set_ylabel("Number of Alerts", fontsize=12)
        ax_bar.bar_label(bars, padding=3, fontsize=10)
        total_alerts = int(np.array(values).sum())
        ax_bar.text(0.99, 0.95, f"Total Alerts: {total_alerts}", ha='right', va='top', transform=ax_bar.transAxes, fontsize=12, bbox=dict(facecolor='white', alpha=0.7, edgecolor='none'))
        ax_bar.text(0.01, 0.95, f"Last Update: {now.strftime('%Y-%m-%d %H:%M:%S')}", ha='left', va='top', transform=ax_bar.transAxes, fontsize=10, color='gray')

        # --- Pie Chart ---
        ax_pie.clear()
        if len(values) > 0:
            wedges, texts, autotexts = ax_pie.pie(values, labels=attack_types, autopct='%1.1f%%', startangle=140, colors=[color_map[a] for a in attack_types], textprops={'fontsize': 10})
            ax_pie.set_title("Alert Proportions by Attack Type", fontsize=14)
        else:
            ax_pie.text(0.5, 0.5, 'No alerts to display', ha='center', va='center', fontsize=12)

        plt.tight_layout(pad=4.0)
        plt.draw()
        plt.pause(5)   # refresh every 5 seconds

    except FileNotFoundError:
        print("ids_alerts.csv not found. Waiting for alerts...")
        time.sleep(5)
    except ValueError as ve:
        print(f"Data error: {ve}")
        time.sleep(5)
    except Exception as e:
        print(f"Error reading alerts: {e}")
        time.sleep(5)

