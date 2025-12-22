import pandas as pd
import sys
import pickle

# Load trained model
model = pickle.load(open("prediction/random_forest_turnout_reg.pkl", "rb"))

# READ INPUTS
num_candidates = float(sys.argv[1])
duration_days = float(sys.argv[2])
total_registered_voters = float(sys.argv[3])
# we still input it, but derived feature is used
total_votes = float(sys.argv[4])   

# CREATE SAME FEATURES AS TRAINED MODEL
votes_per_candidate = total_votes / num_candidates

X = pd.DataFrame([[
    num_candidates,
    duration_days,
    total_registered_voters,
    votes_per_candidate
]], columns=[
    "num_candidates",
    "duration_days",
    "total_registered_voters",
    "votes_per_candidate"
])

# PREDICT
pred = model.predict(X)[0]

print("\n--------------------------------------")
print(f"🔮 Predicted Turnout %: {pred:.2f}%")
print("--------------------------------------\n")
