import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import r2_score, mean_absolute_error
import pickle

df = pd.read_csv("prediction/ml_turnout_features_clean.csv")

# FEATURES TO HELP MODEL LEARN MORE
df["votes_per_candidate"] = df["total_votes"] / df["num_candidates"]
df["turnout_percentage"] = df["turnout_ratio"] * 100 # target in %

X = df[["num_candidates","duration_days","total_registered_voters","votes_per_candidate"]]
y = df["turnout_percentage"]  # 🔥 regression target

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

model = RandomForestRegressor(
    n_estimators=350,       # stronger model
    max_depth=None,         # let trees grow fully
    min_samples_split=2,
    random_state=42
)

model.fit(X_train, y_train)
pred = model.predict(X_test)

print("\n📊 MODEL PERFORMANCE")
print("R² Score:", r2_score(y_test, pred))
print("MAE:", mean_absolute_error(y_test, pred))

# SAVE MODEL
pickle.dump(model, open("prediction/random_forest_turnout_reg.pkl","wb"))
print("\n🔥 Regression Model Saved Successfully!")
