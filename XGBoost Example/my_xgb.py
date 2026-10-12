# -*- coding: utf-8 -*-
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd

# 1. นำเข้าข้อมูล
# (อย่าลืมวางไฟล์ Churn_Modelling.csv ไว้ในโฟลเดอร์เดียวกับไฟล์โค้ด)
dataset = pd.read_csv('Churn_Modelling.csv')
X = dataset.iloc[:, 3:13].values
y = dataset.iloc[:, 13].values

# 2. แปลงข้อมูลที่เป็นข้อความ (Categorical Data) ให้เป็นตัวเลข
from sklearn.preprocessing import LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

# แปลงคอลัมน์ที่ 2 (Gender: เพศ ชาย/หญิง) ด้วย LabelEncoder (ให้กลายเป็น 0 กับ 1)
labelencoder_X_2 = LabelEncoder()
X[:, 2] = labelencoder_X_2.fit_transform(X[:, 2])

# แปลงคอลัมน์ที่ 1 (Geography: ประเทศ) ด้วย OneHotEncoder ผ่าน ColumnTransformer (วิธีแบบใหม่)
# remainder='passthrough' หมายถึงคอลัมน์อื่นๆ ที่ไม่ได้แปลงให้เก็บไว้เหมือนเดิม
ct = ColumnTransformer(transformers=[('encoder', OneHotEncoder(), [1])], remainder='passthrough')
X = np.array(ct.fit_transform(X))

# ตัดคอลัมน์แรกออกเพื่อป้องกันปัญหา Dummy Variable Trap
X = X[:, 1:]

# 3. แบ่งชุดข้อมูลเป็น Training set และ Test set
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.20, random_state = 0)

# 4. ฝึกสอนโมเดล XGBoost
from xgboost import XGBClassifier
# เพิ่ม eval_metric='logloss' เพื่อปิดการแจ้งเตือน (Warning) ของเวอร์ชันใหม่
classifier = XGBClassifier(eval_metric='logloss')
classifier.fit(X_train, y_train)

# 5. ทำนายผลบน Test set
y_pred = classifier.predict(X_test)

# 6. สร้างและแสดง Confusion Matrix
from sklearn.metrics import confusion_matrix, accuracy_score
cm = confusion_matrix(y_test, y_pred)
acc = accuracy_score(y_test, y_pred)

print("=== ผลการประเมินโมเดล (Test Set) ===")
print("Confusion Matrix:\n", cm)
print(f"Accuracy Score: {acc * 100:.2f}%\n")

# 7. ประเมินประสิทธิภาพด้วย K-fold Cross Validation
from sklearn.model_selection import cross_val_score
accuracies = cross_val_score(estimator = classifier, X = X_train, y = y_train, cv = 10, n_jobs = -1)

print("=== ผลการประเมิน K-fold Cross Validation (10 รอบ) ===")
print(f"ความแม่นยำเฉลี่ย (Mean Accuracy): {accuracies.mean() * 100:.2f}%")
print(f"ค่าเบี่ยงเบนมาตรฐาน (Standard Deviation): {accuracies.std() * 100:.2f}%")