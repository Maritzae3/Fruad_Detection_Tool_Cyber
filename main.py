import pandas as pd

#Loading the data below
bank_data = pd.read_csv('./Data/fraud_dataset_200_rows_final.csv')

#preparing the data below
bank_data['timestamp'] = pd.to_datetime(bank_data['timestamp'])
bank_data = bank_data.sort_values(['account_id', 'timestamp']).reset_index(drop=True)

#adding columns to data frame for the results from rules
bank_data['status'] = "Normal"
bank_data['reason'] = ""

#creating date column for daily totals
bank_data["date"] = bank_data["timestamp"].dt.date

#The First Rule: Transactions over $10,0000

transactions_over_10000 = (
    (bank_data['event_type'] == "transaction") &
    (bank_data["amount"] > 10000))
bank_data.loc[transactions_over_10000,'status'] = 'Suspicious'
bank_data.loc[transactions_over_10000,"reason"] += "Transaction amount is over $10,000."


#just checking if produces accurate results
flagged = bank_data[bank_data["status"] == "Suspicious"]
print("\nRule 1 output: ")
print("Total flagged: ", len(flagged))
print(flagged[["account_id", "amount", "status", "reason"]])
