import pandas as pd
import sqlite3
import warnings
from sklearn.ensemble import IsolationForest

MAX_FILE_SIZE = 5e7   # 50 MB
MIN_ENTROPY = 0.5
MAX_ENTROPY = 8.0

def clean_and_save():
    warnings.filterwarnings("ignore", category=FutureWarning)

    db_path = "malware_analytics.db"
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM malware_features_db;", conn)

    # === 1. Threshold Filtering ===
    # กรองขนาดไฟล์และช่วง Entropy ตามเงื่อนไข (ใช้ .copy() เพื่อป้องกัน SettingWithCopyWarning)
    df_threshold = df[
        (df["file_size_bytes"] < MAX_FILE_SIZE) &
        (df["file_entropy"] >= MIN_ENTROPY) &
        (df["file_entropy"] <= MAX_ENTROPY)
    ].copy()

    # === 2. Filter Unused Train Features ===
    # คอลัมน์ที่เป็น String/Identifier ซึ่งโมเดลไม่ได้ใช้ในการเทรน
    unused_columns = ["sha256", "file_name", "magic_bytes", "ssdeep_full", "imphash", "os"]
    
    # ลบคอลัมน์ที่ไม่ใช้ออก (ตรวจสอบก่อนว่ามีคอลัมน์นั้นอยู่ใน DataFrame หรือไม่)
    cols_to_drop = [col for col in unused_columns if col in df_threshold.columns]
    df_threshold.drop(columns=cols_to_drop, inplace=True)

    # === 3. Handle Missing Values ===
    # ลบแถวที่มีค่าว่าง (NaN) ออก เพื่อป้องกัน Error ใน IsolationForest และตอนเทรนโมเดล
    df_threshold.dropna(inplace=True)

    # === 4. Outlier Detection ===
    # เลือกเฉพาะฟีเจอร์ตัวเลขมาคำนวณหา Outlier
    iso_features = ["file_size_bytes", "file_entropy", "block_size", "num_sections"]
    iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    
    # ทำนาย Outlier (-1 คือ Outlier, 1 คือ Inlier)
    df_threshold["outlier_flag"] = iso.fit_predict(df_threshold[iso_features])
    
    # เก็บเฉพาะข้อมูลปกติ (Inlier)
    df_clean = df_threshold[df_threshold["outlier_flag"] == 1].copy()

    # ตัด outlier_flag ออก เพราะไม่ใช่ Feature สำหรับโมเดล
    df_clean.drop(columns=["outlier_flag"], inplace=True)

    # === 5. เขียนกลับเข้า SQLite ===
    # แนะนำ: ให้เขียนลงตารางใหม่ เช่น `malware_features_train_clean` 
    # เพื่อรักษาข้อมูลตารางเดิม `malware_features_db` ไว้ตรวจสอบภายหลัง
    target_table = "malware_features_train_clean"
    df_clean.to_sql(target_table, conn, if_exists="replace", index=False)

    conn.close()
    
    print(f"[+] ข้อมูลเริ่มต้น: {len(df)} แถว")
    print(f"[+] ข้อมูลหลัง Cleaning พร้อมเทรน: {len(df_clean)} แถว")
    print(f"[+] ลบคอลัมน์ที่ไม่ได้ใช้งาน: {cols_to_drop}")
    print(f"[+] เขียนข้อมูลกลับเข้า SQLite (ตาราง {target_table}) เรียบร้อยแล้ว")

    return df_clean