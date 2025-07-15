import matplotlib.pyplot as plt
import pandas as pd
import time

plt.ion()  # turn on interactive mode

while True:
    try:
        # Read the alerts CSV
        df = pd.read_csv("ml_dataset.csv")

        # Count each attack type
        counts = df["Label"].value_counts()

        # Clear previous figure
        plt.clf()

        # Plot as a bar chart
        counts.plot(kind="bar", color="skyblue")
        plt.title("Real-Time IDS Alerts")
        plt.xlabel("Attack Type")
        plt.ylabel("Number of Alerts")
        plt.tight_layout()

        plt.draw()
        plt.pause(5)   # refresh every 5 seconds

    except Exception as e:
        print(f"Error reading alerts: {e}")
        time.sleep(5)

