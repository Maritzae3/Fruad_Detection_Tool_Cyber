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
# flagged = bank_data[bank_data["status"] == "Suspicious"]
# print("\nRule 1 output: ")
# print("Total flagged: ", len(flagged))
# print(flagged[["account_id", "amount", "status", "reason"]])

#The Second Rule: Structured transactions
#measures to the strcutured transaction
struct_transaction =(
    (bank_data["event_type"] == "transaction") &
    (bank_data["amount"] >= 9000) &
    (bank_data["amount"] < 10000)
)

#applying the query to strcutured transaction
bank_data.loc[struct_transaction, "status"] = "Suspicious"
bank_data.loc[struct_transaction, "reason"] += "The transaction is near $10,000.(structured transaction)"

#Uncomment to see results of Rule 2
# flagged = bank_data[bank_data["status"] == "Suspicious"]
# print("\nRule 2 output: ")
# print("Total flagged: ", len(flagged))
# print(flagged[["account_id", "amount", "status", "reason"]])

#The Third Rule: Daily over $25,000

#Grouping the account id , dat and amount and based on account and date 
#sums the ammount based on same day transactions by date, accnt id & amount
daily_total_for_account = (
    bank_data[bank_data["event_type"] == "transaction"]
    .groupby(["account_id", "date"])["amount"]
    .transform("sum")
)

#Determines wether daily transactions limit went overboard
daily_total_ovr_limit = (
    (bank_data["event_type"] == "transaction") &
    (daily_total_for_account > 25000)
)
#updates and looks for accounts that violate this standard
bank_data.loc[daily_total_ovr_limit, "status"] = "Suspicious"
bank_data.loc[daily_total_ovr_limit, "reason"] += "Daily total over $25,000."

#Uncomment to see results of Rule 3
# flagged = bank_data[bank_data["status"] == "Suspicious"]
# print("\nRule 3 output: ")
# print("Total flagged: ", len(flagged))
# print(flagged[["account_id", "amount", "status", "reason"]])

#Rule number 4: Multiple failed login attempts followed by an successful attempt

#looping through each accnt seperately
for account_id, account_data in bank_data.groupby("account_id"):
    account_data = account_data.sort_values("timestamp")

    for row_index in account_data.index:
        current_event = bank_data.loc[row_index]

# Find failed login attempts within the last 30 minutes BEFORE this login
        if current_event["event_type"] == "login" and current_event["login_success"] == 1:
            recent_failed_logins = account_data[
                (account_data["event_type"] == "login") &
                (account_data["timestamp"] >= current_event["timestamp"] - pd.Timedelta(minutes=30)) &
                (account_data["timestamp"] < current_event["timestamp"]) &
                (account_data["login_success"] == 0)
            ]

        # If there are 2 or more failed attempts → suspicious
            if len(recent_failed_logins) >= 2:
                bank_data.loc[row_index, "status"] = "Suspicious"
                bank_data.loc[row_index, "reason"] += "Multiple failed login attempts followed by an successful attempt"


#Uncomment to see results of Rule 4  
rule4_results = bank_data[
    bank_data["reason"].str.contains("Multiple failed login attempts followed by an successful attempt", na=False)
]
print("\nRule 4 Check:")
print("Total flagged by Rule 4:", len(rule4_results))
print("\nSample flagged rows:")
print(rule4_results[[
    "account_id",
    "timestamp",
    "event_type",
    "login_success",
    "reason"
]].head(10))

#Rule number 5: IP address located in a country inconsistent with user history / (time intervals, location distance, account ID)




