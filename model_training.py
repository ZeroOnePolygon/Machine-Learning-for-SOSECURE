# นำเข้าไลบรารีที่จำเป็นสำหรับการทำงาน
import sqlite3               # จัดการฐานข้อมูล SQLite
import warnings              # จัดการการแจ้งเตือน
import numpy as np           # คำนวณทางคณิตศาสตร์และการจัดการ Array
import pandas as pd          # จัดการข้อมูลแบบตาราง (DataFrame)
import seaborn as sns        # วาดกราฟและจัดรูปแบบกราฟให้สวยงาม
import matplotlib.pyplot as plt # วาดกราฟพื้นฐาน
import xgboost as xgb        # อัลกอริทึม Machine Learning (XGBoost)
from sklearn.metrics import ( # ฟังก์ชันสำหรับวัดประสิทธิภาพโมเดล
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
    precision_score,
    recall_score
)
from sklearn.model_selection import train_test_split # ฟังก์ชันแบ่งชุดข้อมูล

def model_train_optimized():
    # ปิดการแสดงข้อความแจ้งเตือน (Warning) เพื่อให้หน้าจอแสดงผลสะอาดตา
    warnings.filterwarnings("ignore")

    # === ขั้นตอนที่ 1: โหลดข้อมูลจากตารางที่ผ่านการ Clean แล้ว ===
    print("\n=== ขั้นตอนที่ 1: โหลดข้อมูลจาก SQLite (ตาราง Cleaned) ===")
    db_path = "malware_analytics.db" # กำหนดที่อยู่ของไฟล์ฐานข้อมูล
    conn = sqlite3.connect(db_path)  # เปิดการเชื่อมต่อฐานข้อมูล

    # เขียนคำสั่ง SQL เพื่อดึงข้อมูลเฉพาะคอลัมน์ที่เป็นฟีเจอร์และเป้าหมาย
    query = "SELECT file_size_bytes, file_entropy, block_size, num_sections, threat FROM malware_features_train_clean;"
    df = pd.read_sql_query(query, conn) # ดึงข้อมูลมาเก็บในรูปแบบตาราง (Pandas DataFrame)
    conn.close() # ปิดการเชื่อมต่อฐานข้อมูล

    print(f"[*] โหลดข้อมูลสำเร็จ ขนาดข้อมูล: {df.shape}")

    # === ขั้นตอนที่ 2: จัดเรียงและกำหนดลำดับ X, y ให้ชัดเจน ===
    print("\n=== ขั้นตอนที่ 2: กำหนดลำดับ Features ===")
    # เลือกชื่อคอลัมน์ที่จะใช้เป็นตัวแปรต้น (Features)
    feature_columns = [
        "file_size_bytes",
        "file_entropy",
        "block_size",
        "num_sections",
    ]

    X = df[feature_columns] # ตัวแปรต้น (สิ่งที่โมเดลใช้เรียนรู้)
    y = df["threat"]        # ตัวแปรตาม/เป้าหมาย (0 = ปกติ, 1 = มัลแวร์)

    print(f"[*] ลำดับ Features ที่ใช้เทรน (4 ตัว): {feature_columns}")

    # === ขั้นตอนที่ 3: แบ่งกลุ่มข้อมูลแบบ Stratified ===
    print("\n=== ขั้นตอนที่ 3: แบ่งกลุ่มข้อมูลแบบ Stratified ===")
    # แบ่งครั้งที่ 1: แบ่งเป็น Temp (80%) และ Test (20%)
    # stratify=y ช่วยกระจายสัดส่วนของคลาส 0 และ 1 ให้เท่ากันในทุกชุดข้อมูล
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # แบ่งครั้งที่ 2: เอา Temp (80%) มาแบ่งเป็น Train (60%) และ Validation (20%)
    # test_size=0.25 ของ 80% คือ 20% ของข้อมูลทั้งหมด
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.25, random_state=42, stratify=y_temp
    )

    print(f"[*] Train set      : {X_train.shape} (60%)")
    print(f"[*] Validation set : {X_val.shape} (20%)")
    print(f"[*] Test set       : {X_test.shape} (20%)")

    # === ขั้นตอนที่ 4: ฝึกโมเดล XGBoost ===
    print("\n=== ขั้นตอนที่ 4: ฝึกโมเดล XGBoost ===")
    # คำนวณอัตราส่วนของคลาส 0 ต่อคลาส 1 เพื่อแก้ปัญหา Imbalanced Data
    scale_pos_weight = len(y_train[y_train == 0]) / len(y_train[y_train == 1])

    # กำหนดค่าพารามิเตอร์ (Hyperparameters) สำหรับการสร้างโมเดล XGBoost
    model = xgb.XGBClassifier(
        n_estimators=500,           # จำนวนต้นไม้ (รอบการเรียนรู้สูงสุด)
        max_depth=5,                # ความลึกสูงสุดของต้นไม้
        learning_rate=0.03,         # อัตราการเรียนรู้ (ยิ่งน้อยยิ่งละเอียด แต่ช้า)
        subsample=0.8,              # สุ่มข้อมูลมาเทรน 80% ต่อรอบ (ลด Overfitting)
        colsample_bytree=1.0,       # ใช้คอลัมน์ทั้งหมดในการสร้างต้นไม้
        min_child_weight=3,         # ควบคุมการแตกกิ่ง (ลด Overfitting)
        reg_alpha=0.1,              # L1 Regularization
        reg_lambda=1.0,             # L2 Regularization
        scale_pos_weight=scale_pos_weight, # ให้น้ำหนักคลาสที่มีจำนวนน้อยกว่า
        eval_metric="logloss",      # ใช้ Log Loss เป็นตัววัดผลระหว่างเทรน
        early_stopping_rounds=30,   # หยุดเทรนถ้าโมเดลไม่พัฒนาขึ้นภายใน 30 รอบ
        random_state=42,            # ล็อกค่าการสุ่มให้ได้ผลลัพธ์เหมือนเดิมทุกครั้ง
    )

    # สั่งให้โมเดลเริ่มเรียนรู้ (Train)
    model.fit(
        X_train,
        y_train,
        eval_set=[(X_train, y_train), (X_val, y_val)], # ใช้ Validation set ประเมินระหว่างเทรน
        verbose=False, # ปิดการแสดงผลคะแนนในแต่ละรอบ
    )

    best_iter = model.best_iteration # ดึงจำนวนรอบที่ดีที่สุดที่โมเดลหยุดเทรน
    print(f"[+] ฝึกโมเดลเสร็จสิ้น (Best Iteration: ต้นไม้ที่ {best_iter})")

    # === ขั้นตอนที่ 5: ปรับหา Best Threshold ===
    print("\n=== ขั้นตอนที่ 5: ปรับ Threshold ด้วย Validation Set ===")
    # ให้โมเดลทำนายโอกาสเป็นมัลแวร์ (Probability) บน Validation Set
    y_val_proba = model.predict_proba(X_val)[:, 1] 
    
    # คำนวณ Precision และ Recall ในแต่ละจุดตัด (Threshold)
    precision, recall, thresholds = precision_recall_curve(y_val, y_val_proba)

    # คำนวณหาค่า F1-Score ในทุกๆ Threshold (บวก 1e-9 เพื่อป้องกันการหารด้วย 0)
    f1_scores_val = 2 * (precision * recall) / (precision + recall + 1e-9)
    best_idx = np.argmax(f1_scores_val) # หาตำแหน่ง (Index) ที่ได้ F1-Score สูงสุด
    best_threshold = float(thresholds[best_idx]) # ดึงค่า Threshold ที่ดีที่สุดออกมา

    print(f"[+] Threshold ที่ได้ F1-Score สูงที่สุด: {best_threshold:.4f}")

    # === ขั้นตอนที่ 6: ประเมินผลบน Test Set ===
    print("\n=== ขั้นตอนที่ 6: ประเมินผลบน Test Set ===")
    # ทำนายผลบนชุดข้อมูล Test
    y_test_proba = model.predict_proba(X_test)[:, 1]
    # แปลงผลลัพธ์ความน่าจะเป็นให้เป็น 0 หรือ 1 โดยใช้ Threshold ที่หาได้จากขั้นตอนที่ 5
    y_pred = (y_test_proba >= best_threshold).astype(int)

    # คำนวณตัวชี้วัดประสิทธิภาพ (Metrics)
    acc = accuracy_score(y_test, y_pred) # ความแม่นยำรวม
    prec = precision_score(y_test, y_pred) # ความแม่นยำเมื่อทายว่าเป็นมัลแวร์
    rec = recall_score(y_test, y_pred) # ความสามารถในการจับมัลแวร์ที่มีอยู่จริง
    f1 = f1_score(y_test, y_pred) # ค่าเฉลี่ยความสมดุลของ Precision และ Recall
    auc = roc_auc_score(y_test, y_test_proba) # พื้นที่ใต้กราฟ ROC

    print(f"[*] Accuracy  : {acc:.4f}")
    print(f"[*] Precision : {prec:.4f}")
    print(f"[*] Recall    : {rec:.4f}")
    print(f"[*] F1 Score  : {f1:.4f}")
    print(f"[*] ROC-AUC   : {auc:.4f}")
    
    print("\n[+] Classification Report:")
    print(classification_report(y_test, y_pred, digits=4)) # สรุปผลรายคลาส
    print("[+] Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred)) # ตารางแจกแจงการทายถูก/ผิด

    # === แสดงกราฟเปรียบเทียบ Metrics ===
    # สร้าง DataFrame สำหรับเตรียมนำไปวาดกราฟ
    df_metrics = pd.DataFrame({
        "Metric": ["Accuracy", "Precision", "Recall", "F1-Score"],
        "Score": [acc, prec, rec, f1]
    })

    plt.figure(figsize=(8, 5)) # กำหนดขนาดกราฟ
    # สร้างกราฟแท่งด้วย Seaborn
    ax = sns.barplot(
        x="Metric", 
        y="Score", 
        data=df_metrics, 
        palette=["#3498db", "#9b59b6", "#e67e22", "#2ecc71"] # กำหนดสีกราฟ
    )
    
    plt.title("Model Evaluation Metrics (Test Set)", fontsize=14, fontweight="bold")
    plt.ylim(0, 1.1) # กำหนดแกน Y ให้อยู่ระหว่าง 0 ถึง 1.1 (เต็ม 100%)
    plt.ylabel("Score", fontsize=12)
    plt.xlabel("")
    
    # วนลูปเพื่อเขียนตัวเลขกำกับไว้บนยอดของกราฟแท่งแต่ละอัน
    for p in ax.patches:
        ax.annotate(
            f"{p.get_height():.4f}", 
            (p.get_x() + p.get_width() / 2., p.get_height()), 
            ha="center", 
            va="bottom", 
            fontsize=12, 
            fontweight="bold",
            color="black", 
            xytext=(0, 5), 
            textcoords="offset points"
        )

    plt.grid(axis="y", linestyle="--", alpha=0.6) # เพิ่มเส้นกริดแนวนอน
    plt.tight_layout() # จัดรูปแบบกราฟไม่ให้ข้อความทับกัน
    plt.show() # สั่งแสดงกราฟ

    # === ขั้นตอนที่ 7: บันทึกโมเดล ===
    print("\n=== ขั้นตอนที่ 7: บันทึกโมเดล ===")
    model_filename = "malware_modelV2.bin" # ตั้งชื่อไฟล์โมเดลที่จะบันทึก
    booster = model.get_booster() # ดึงแกนหลักการเรียนรู้ (Booster) ออกมาจาก XGBoost
    booster.save_model(model_filename) # บันทึกเป็นไฟล์ .bin

    print(f"[+] บันทึกโมเดลสำเร็จลงไฟล์ '{model_filename}'")


# จุดเริ่มต้นการทำงานของสคริปต์
if __name__ == "__main__":
    model_train_optimized() # เรียกใช้งานฟังก์ชันหลัก