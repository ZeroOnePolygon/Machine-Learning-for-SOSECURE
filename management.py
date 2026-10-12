import sqlite3
import os


def merge_sqlite_databases(main_db_name, source_databases):
    """
    Merges multiple SQLite databases into one main database.
    Uses INSERT OR IGNORE to automatically discard duplicate SHA256 hashes.
    """
    # 1. Connect to your main/target database
    conn = sqlite3.connect(main_db_name)
    cursor = conn.cursor()
    
    # 2. Loop through every database you want to merge
    for source_db in source_databases:
        # Skip if the file doesn't exist or if it's the main database itself
        if not os.path.exists(source_db) or source_db == main_db_name:
            continue
            
        print(f"Merging: {source_db} -> {main_db_name}")
        
        try:
            # Attach the secondary database to our current connection
            cursor.execute(f"ATTACH DATABASE '{source_db}' AS db_to_merge;")
            
            # Copy all records over. The 'IGNORE' keyword ensures duplicate primary keys are skipped.
            cursor.execute("""
                INSERT OR IGNORE INTO main.malware_features_db 
                SELECT * FROM db_to_merge.malware_features_db;
            """)
            
            # Save the transaction and detach the secondary database
            conn.commit()
            cursor.execute("DETACH DATABASE db_to_merge;")
            print(f"  [+] Successfully merged {source_db}")
            
        except sqlite3.OperationalError as e:
            print(f"  [-] Error merging {source_db}: {e}")

    conn.close()
    print("\nAll database merges completed successfully.")

def clean_database(DB_PATH,TARGET_EXTENSIONS):
    if not os.path.exists(DB_PATH):
        print(f"[!] Error: ไม่พบไฟล์ฐานข้อมูล '{DB_PATH}'")
        return

    print("=== Malware Database Cleanup Utility ===")
    
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        
        # 1. ดึงข้อมูลทั้งหมดขึ้นมาตรวจสอบ
        cursor.execute("SELECT sha256, file_name FROM malware_features_db")
        records = cursor.fetchall()
        
        total_records = len(records)
        print(f"[*] กำลังสแกน... พบข้อมูลทั้งหมดในระบบ: {total_records} รายการ")
        
        # 2. คัดแยกไฟล์ขยะ (Noise)
        junk_hashes = []
        junk_examples = set() # เก็บตัวอย่างนามสกุลขยะไว้แสดงให้ดู
        
        for sha256, file_name in records:
            ext = os.path.splitext(file_name)[1].lower()
            if ext not in TARGET_EXTENSIONS:
                junk_hashes.append((sha256,))
                if len(junk_examples) < 10:
                    junk_examples.add(ext if ext else "[ไม่มีนามสกุล]")
                
        if not junk_hashes:
            print("[+] ยอดเยี่ยม! ฐานข้อมูลของคุณคลีน 100% ไม่มีไฟล์ขยะต้องลบ")
            return
            
        print(f"\n[!] ตรวจพบไฟล์ที่ไม่เกี่ยวข้อง (Noise) จำนวน: {len(junk_hashes)} รายการ")
        print(f"    ตัวอย่างนามสกุลขยะที่พบ: {', '.join(junk_examples)} ...")
        
        # 3. ยืนยันการลบ
        confirm = input("\nต้องการลบข้อมูลขยะเหล่านี้ทิ้งอย่างถาวรใช่หรือไม่? (y/n): ").strip().lower()
        
        if confirm == 'y':
            # 1. ลบข้อมูลแบบ Batch (เปิด Transaction อัตโนมัติ)
            cursor.executemany("DELETE FROM malware_features_db WHERE sha256 = ?", junk_hashes)
            
            # [FIX] 2. ต้อง Commit เพื่อปิด Transaction การลบให้เสร็จสมบูรณ์ก่อน
            conn.commit()
            
            print("[*] กำลังจัดเรียงข้อมูลและคืนพื้นที่ว่าง (VACUUM)...")
            # 3. รัน VACUUM นอก Transaction ได้อย่างปลอดภัย
            cursor.execute("VACUUM") 
            
            print(f"\n[+] ล้างข้อมูลสำเร็จ! กวาดไฟล์ขยะไป {len(junk_hashes)} รายการ")
            print(f"[+] ข้อมูลคุณภาพสูง (Clean Data) ที่เหลืออยู่: {total_records - len(junk_hashes)} รายการ")
        else:
            print("\n[-] ยกเลิกการทำความสะอาดฐานข้อมูล")
