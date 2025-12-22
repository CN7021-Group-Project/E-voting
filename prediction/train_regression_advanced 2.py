import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import r2_score, mean_absolute_error
import pickle

df = pd.read_csv("prediction/ml_turnout_features_clean.csv")

# features to help model learn more
df["votes_per_candidate"] = df["total_votes"] / df["num_candidates"]
# target in %
df["turnout_percentage"] = df["turnout_ratio"] * 100 

X = df[["num_candidates","duration_days","total_registered_voters","votes_per_candidate"]]
# regression target
y = df["turnout_percentage"]  

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

model = RandomForestRegressor(
    # stronger model
    n_estimators=350,     
    # let trees grow fully  
    max_depth=None,         
    min_samples_split=2,
    random_state=42
)

model.fit(X_train, y_train)
pred = model.predict(X_test)

print("\n📊 MODEL PERFORMANCE")
print("R² Score:", r2_score(y_test, pred)) # regression score function
print("MAE:", mean_absolute_error(y_test, pred))

# save model
pickle.dump(model, open("prediction/random_forest_turnout_reg.pkl","wb"))
print("\n🔥 Regression Model Saved Successfully!")
