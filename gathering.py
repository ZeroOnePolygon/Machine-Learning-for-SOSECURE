import concurrent.futures
import os
import sqlite3
import tkinter as tk
from tkinter import filedialog
from tqdm import tqdm

# ดึงฟังก์ชันช่วยสแกนและดึงข้อมูลไฟล์จากไฟล์ Features_gathering.py
import Features_gathering as process

# ==========================================
# 1. การตั้งค่าเริ่มต้น (CONFIGURATION)
# ==========================================
MAX_SIZE = 20 * 1024 * 1024  # ขนาดไฟล์สูงสุดที่ไม่เกิน 20 MB
LIMIT = 50000  # จำนวนไฟล์สูงสุดที่จะรับมาประมวลผล
WORKERS = max(1, (os.cpu_count() or 2) - 1)  # จำนวน CPU Cores ที่จะใช้ทำงานขนานกัน

# ตั้งค่าเส้นทางเก็บไฟล์ฐานข้อมูลให้อยู่ที่เดียวกับไฟล์โค้ดนี้
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "malware_analytics.db")

BATCH_SIZE = 1000  # สะสมครบ 1,000 ไฟล์แล้วค่อยเซฟลง Database ทีเดียว


# ==========================================
# 2. ฟังก์ชันสำหรับบันทึกข้อมูลลง Database
# ==========================================
def save_batch_to_db(data_batch):
    """ฟังก์ชันทำหน้าที่แปลงข้อมูลให้เรียบร้อย แล้วเซฟลงฐานข้อมูล SQLite"""
    # ถ้าไม่มีข้อมูลในชุดนี้ ให้ข้ามไปเลย
    if not data_batch:
        return

    # รายชื่อคอลัมน์ทั้งหมดในตารางฐานข้อมูล
    expected_columns = [
        'sha256',
        'file_name',
        'file_size_bytes',
        'magic_bytes',
        'block_size',
        'ssdeep_full',
        'file_entropy',
        'imphash',
        'os',
        'feat_double_ext',
        'feat_susp_score',
        'feat_mismatch',
        'num_sections',
        'threat',
    ]

    data_tuples = []
    seen_hashes = set()  # ใช้เช็กป้องกันไม่ให้มีไฟล์ค่า SHA256 ซ้ำกันในกลุ่มเดียวกัน

    # ลูปเพื่อตรวจสอบและทำความสะอาดข้อมูลก่อนเซฟ
    for item in data_batch:
        if not isinstance(item, dict):
            continue

        file_hash = item.get('sha256')

        # เช็กว่าเคยเจอ Hash นี้ใน Batch เดียวกันหรือยัง (กันข้อมูลซ้ำ)
        if file_hash and file_hash not in seen_hashes:
            seen_hashes.add(file_hash)

            row = []
            for col in expected_columns:
                val = item.get(col)

                # ถ้าข้อมูลตัวไหนว่างเปล่า (None) ให้ใส่ค่าเริ่มต้นแทน ป้องกัน DB พัง
                if val is None:
                    if col in [
                        'file_size_bytes',
                        'block_size',
                        'feat_double_ext',
                        'feat_susp_score',
                        'feat_mismatch',
                        'num_sections',
                        'threat',
                    ]:
                        val = 0  # ตัวเลขจำนวนเต็ม
                    elif col == 'file_entropy':
                        val = 0.0  # ตัวเลขทศนิยม
                    else:
                        val = 'Unknown'  # ข้อความ

                row.append(val)

            # แปลงข้อมูล 1 ข้อมูลให้อยู่ในรูป Tuple
            data_tuples.append(tuple(row))

    if not data_tuples:
        return

    # บันทึกลงฐานข้อมูล SQLite
    try:
        # timeout=20 ป้องกันปัญหาฐานข้อมูลล็อกเวลาเขียนข้อมูลหนักๆ
        with sqlite3.connect(DB_PATH, timeout=20) as conn:
            cursor = conn.cursor()
            cols_str = ', '.join(expected_columns)
            placeholders = ', '.join(['?'] * len(expected_columns))

            # ใช้ INSERT OR IGNORE เพื่อถ้าเจอไฟล์ซ้ำกับที่มีอยู่แล้วใน DB ให้ข้ามไป ไม่ให้โปรแกรมเด้งดับ
            sql_query = f'INSERT OR IGNORE INTO malware_features_db ({cols_str}) VALUES ({placeholders})'

            cursor.executemany(sql_query, data_tuples)
            conn.commit()  # ยืนยันการบันทึก
    except sqlite3.Error as db_err:
        print(f'\n[!] เกิดข้อผิดพลาด SQL ขณะบันทึกข้อมูล: {db_err}')


# ==========================================
# 3. ฟังก์ชันหลักในการทำงาน (MAIN PROCESS)
# ==========================================
def Data_gathering():
    """ฟังก์ชันหลัก: รับค่าจากผู้ใช้, เลือกโฟลเดอร์, ดึงข้อมูลไฟล์ และบันทึกผล"""

    # --- ขั้นตอนที่ 1: เตรียมฐานข้อมูล ---
    process.init_database(DB_PATH)
    with sqlite3.connect(DB_PATH) as conn:
        # เปิด WAL Mode ช่วยให้เขียนและอ่านฐานข้อมูลได้เร็วขึ้นมาก
        conn.execute('PRAGMA journal_mode=WAL;')

    print('=== โปรแกรมเก็บรวบรวมข้อมูลไฟล์ (Data Harvester) ===')

    # --- ขั้นตอนที่ 2: ถามระดับความเสี่ยงจากผู้ใช้ ---
    threat_input = input(
        'กรอกระดับความเสี่ยงของโฟลเดอร์นี้ (0 = ไฟล์ปกติ, 1 = มัลแวร์) [ค่าเริ่มต้น: 0]: '
    ).strip()
    current_threat_level = 1 if threat_input == '1' else 0

    # --- ขั้นตอนที่ 3: เปิดหน้าต่าง Pop-up ให้เลือกโฟลเดอร์ ---
    root = tk.Tk()
    root.withdraw()  # ซ่อนหน้าต่างหลักของ Tkinter ไว้
    root.attributes('-topmost', True)  # บังคับให้ Pop-up เด้งมาข้างหน้าสุด

    print('กำลังเปิดหน้าต่างให้เลือกโฟลเดอร์...')
    user_dir = filedialog.askdirectory(
        title=f'เลือกโฟลเดอร์สำหรับระดับความเสี่ยง: {current_threat_level}'
    )

    # ถ้าผู้ใช้กดปิด หรือยกเลิก ไม่เลือกโฟลเดอร์
    if not user_dir:
        print('[!]ไม่ได้เลือกโฟลเดอร์ ยุติการทำงาน...')
        return

    target_dir = os.path.normpath(user_dir)

    if not os.path.exists(target_dir):
        print(f"[!] ไม่พบโฟลเดอร์: '{target_dir}'")
        return

    # --- ขั้นตอนที่ 4: ค้นหาไฟล์ในโฟลเดอร์ ---
    print(f"\nกำลังสแกนหาไฟล์ใน '{target_dir}'...")
    valid_files = process.get_files_fast(target_dir, LIMIT, MAX_SIZE)

    # สร้างรายการงาน (Tasks) เพื่อส่งให้แต่ละ CPU Core นำไปประมวลผล
    tasks = [
        (file_path, file_size, current_threat_level, DB_PATH, set())
        for file_path, file_size in valid_files
    ]

    print(
        f'เริ่มประมวลผลด้วย CPU {WORKERS} Cores สำหรับทั้งหมด {len(tasks)} ไฟล์...'
    )

    # --- ขั้นตอนที่ 5: เริ่มประมวลผลแบบขนาน (Multiprocessing) ---
    buffer_batch = []
    total_saved = 0
    error_count = 0

    # ใช้ ProcessPoolExecutor เพื่อกระจายงานให้หลายๆ CPU ช่วยกันทำ
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=WORKERS
    ) as executor:
        # ส่งงานเข้าคิวประมวลผล
        futures = {
            executor.submit(process.process_file_data, task): task
            for task in tasks
        }

        # รูปแบบของแถบแสดงความคืบหน้า (Progress Bar)
        progress_format = '{desc}: {percentage:3.2f}% |{bar}| {n_fmt}/{total_fmt} ไฟล์ [ผ่านไป: {elapsed} < เหลืออีก: {remaining}]'

        # สร้าง Progress Bar ด้วย tqdm
        with tqdm(
            total=len(tasks),
            desc='กำลังเก็บข้อมูล',
            unit='file',
            bar_format=progress_format,
        ) as pbar:
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result is not None:
                        buffer_batch.append(result)

                        # ถ้าสะสมข้อมูลครบ BATCH_SIZE (1,000 ไฟล์) ให้บันทึกลง DB ทันที
                        if len(buffer_batch) >= BATCH_SIZE:
                            try:
                                save_batch_to_db(buffer_batch)
                                total_saved += len(buffer_batch)
                            except Exception as save_err:
                                print(
                                    f'\n[!] เกิดข้อผิดพลาดในการบันทึกกลุ่มข้อมูล: {save_err}'
                                )
                            finally:
                                # ล้างข้อมูลในพักแรมออกเสมอ ไม่ว่าเซฟผ่านหรือพัง
                                buffer_batch.clear()

                except Exception:
                    error_count += 1

                # อัปเดตแถบความคืบหน้าเพิ่มขึ้น 1 ไฟล์
                pbar.update(1)

    # --- ขั้นตอนที่ 6: เก็บตกข้อมูลส่วนที่เหลือ ---
    if buffer_batch:
        try:
            save_batch_to_db(buffer_batch)
            total_saved += len(buffer_batch)
        except Exception as final_err:
            print(
                f'\n[!] เกิดข้อผิดพลาดในการบันทึกกลุ่มข้อมูลชุดสุดท้าย: {final_err}'
            )
        finally:
            buffer_batch.clear()

    # --- สรุปผลการทำงาน ---
    print(
        f'\n[+] เสร็จสิ้น! บันทึกข้อมูลลงฐานข้อมูลเรียบร้อยแล้วทั้งหมด {total_saved} รายการ'
    )
    if error_count > 0:
        print(
            f'[!] พบข้อผิดพลาดระหว่างทำงาน {error_count} ไฟล์ (เช่น ไม่มีสิทธิ์เข้าถึง หรือไฟล์เสีย)'
        )


# สั่งให้ทำงานเมื่อรันไฟล์นี้โดยตรง
if __name__ == '__main__':
    Data_gathering()