import pandas as pd
from sklearn.ensemble import IsolationForest


class SIEM_AI_Model:

    def __init__(self):
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.is_trained = False

    def train(self, df):
        df = df.copy()

        # حماية لو العمود ناقص
        if "Event ID" not in df.columns:
            df["Event ID"] = 0

        df["event_score"] = df["Event ID"].astype(int)

        self.model.fit(df[["event_score"]])
        self.is_trained = True

    def predict(self, df):

        if not self.is_trained:
            return ["Unknown"] * len(df)

        df = df.copy()

        if "Event ID" not in df.columns:
            df["Event ID"] = 0

        df["event_score"] = df["Event ID"].astype(int)

        preds = self.model.predict(df[["event_score"]])

        return ["Threat" if p == -1 else "Normal" for p in preds]