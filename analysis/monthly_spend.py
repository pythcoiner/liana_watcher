import matplotlib.pyplot as plt
from datetime import datetime
import pandas as pd
import re

def process_file(file_path):
    data = []

    with open(file_path, 'r') as file:
        pattern = re.compile(r'(\d+):([a-fA-F0-9]+):Amount\(([\d\.]+) BTC\)')
        for line in file:
            match = pattern.match(line.strip())
            if match:
                timestamp, txid, amount = match.groups()
                date = datetime.fromtimestamp(int(timestamp))
                data.append(date)

    return data

def aggregate_by_month(dates):
    df = pd.DataFrame(dates, columns=['Date'])
    df.set_index('Date', inplace=True)
    # Resample the data by month and count the number of transactions
    monthly_data = df.resample('M').size()
    return monthly_data

def aggregate_by_week(dates):
    df = pd.DataFrame(dates, columns=['Date'])
    df.set_index('Date', inplace=True)
    # Resample the data by month and count the number of transactions
    monthly_data = df.resample('W').size()
    return monthly_data

def plot_data(monthly_data):
    monthly_data.plot(kind='bar', figsize=(10, 6))
    plt.title('Weekly Liana spend signet')
    plt.xlabel('Month')
    plt.ylabel('txs')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# Main function
def main():
    file_path = 'signet.txt'
    dates = process_file(file_path)
    monthly_data = aggregate_by_week(dates)
    plot_data(monthly_data)

if __name__ == '__main__':
    main()
