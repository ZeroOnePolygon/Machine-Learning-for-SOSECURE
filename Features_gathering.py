import os
import ppdeep
import sqlite3
import pefile
import hashlib
import io
from elftools.elf.elffile import ELFFile
import zipfile
import struct
from collections import Counter
import math
import re
import sys

def init_database(db_name="malware_analytics.db"):
    # 1. ตรวจสอบและสร้างโฟลเดอร์หากยังไม่มี
    db_dir = os.path.dirname(db_name)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
        print(f"[*] Created missing directory for database: {db_dir}")

    # 2. เชื่อมต่อฐานข้อมูล (ถ้าไม่มีไฟล์ SQLite ระบบจะสร้างไฟล์ให้เอง)
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS malware_features_db (
        sha256 TEXT PRIMARY KEY,
        file_name TEXT NOT NULL,
        file_size_bytes INTEGER NOT NULL,
        magic_bytes TEXT NOT NULL,
        block_size INTEGER NOT NULL,
        ssdeep_full TEXT NOT NULL,
        file_entropy REAL NOT NULL,
        imphash TEXT,
        os TEXT NOT NULL,
        feat_double_ext INTEGER NOT NULL,
        feat_susp_score INTEGER NOT NULL,
        feat_mismatch INTEGER NOT NULL,
        num_sections INTEGER NOT NULL, 
        threat INTEGER NOT NULL
    );
    """)
    
    try:
        # พยายามเพิ่มคอลัมน์ในกรณีที่เป็นฐานข้อมูลเวอร์ชันเก่า
        cursor.execute("ALTER TABLE malware_features_db ADD COLUMN num_sections INTEGER NOT NULL DEFAULT 0;")
    except sqlite3.OperationalError:
        pass # ถ้ามีคอลัมน์อยู่แล้วก็ข้ามไป
        
    conn.commit()
    return conn

# ==========================================
# 1. Feature Engineering Functions
# ==========================================
def detect_double_extension(file_name):
    """
    [ปรับปรุงตาม SSDeep.pdf หน้า 19] ตรวจจับนามสกุลซ้อนเชิงพฤติกรรมอันตราย 
    แก้ไขช่องโหว่การ Evasion (เช่น การจงใจใส่ช่องว่างหลอกตา) และป้องกันข้อผิดพลาดเชิงอคติของโมเดล
    """
    if not isinstance(file_name, str):
        return 0

    # 1. ขยายชุดนามสกุลปลายทางที่มีความเสี่ยงสูงในการรันโค้ดคำสั่งอันตราย
    dangerous_extensions = {
        'exe', 'com', 'pif', 'scr', 'cpl', 'msi', 'bat', 'cmd', 
        'vbs', 'js', 'wsf', 'ps1', 'jar', 'sh', 'apk', 'hta', 'lnk', 'vbe'
    }
    
    file_name_lower = file_name.lower().strip()
    
    # ดักจับเทคนิคระดับสูง: Right-to-Left Override (U+202E) ที่แฮกเกอร์มักใช้สลับชื่อไฟล์ให้เหยื่อสับสน เช่น exe.pdf -> fdp.exe
    if '\u202e' in file_name_lower:
        return 1
    
    # แยกส่วนประกอบด้วยจุด พร้อมทำความสะอาดช่องว่างของทุกส่วนย่อยยิบ (ป้องกัน Evasion แบบ invoice.pdf     .exe)
    parts = [p.strip() for p in file_name_lower.split('.') if p.strip()]
    
    # หากมีการใช้จุดซ้อนจนเกิดส่วนประกอบตั้งแต่ 3 ส่วนขึ้นไป
    if len(parts) >= 3: 
        final_ext = parts[-1]        # นามสกุลท้ายสุดจริงๆ (เช่น exe)
        
        # ปรับปรุงโครงสร้าง: ถ้าลงท้ายด้วยไฟล์รันระบบที่เป็นอันตราย และมีนามสกุลอื่นใดมาก่อนหน้า 
        # ให้โมเดลเรียนรู้ว่าเป็นพฤติกรรมสอดไส้ทันที เพื่อตัดปัญหา Bias จากสถิติที่ไม่สมบูรณ์ในอดีต
        if final_ext in dangerous_extensions:
            return 1
            
    return 0

def calculate_suspicious_score(file_name):
    """
    [ปรับปรุงเพื่อลด Noise และลด False Positive] คำนวณคะแนนความน่าสงสัยโดยอิงขอบเขตคำ (Word Boundaries)
    เพื่อป้องกันไม่ให้ไฟล์ซอฟต์แวร์ปกติ (เช่น window_installer_v2.png) ถูกประเมินผิดพลาด
    """
    if not isinstance(file_name, str):
        return 0

    keywords = [
        # 1. กลุ่มหลอกลวงทางการเงินและเอกสารธุรกิจ (Phishing & BEC Lures)
        'invoice', 'receipt', 'payment', 'billing', 'order', 'statement', 
        'po_', 'quote', 'quotation', 'document', 'urgent', 'swift', 'tax', 'scan',

        # 2. กลุ่มซอฟต์แวร์เถื่อนและแคร็ก (Piracy, Cracks & Cheats)
        'crack', 'keygen', 'patch', 'activator', 'cheat', 'hack', 'mod', 
        'bypass', 'nulled', 'cracked', 'premium', 'unlock', 'generator',

        # 3. กลุ่มโปรแกรมติดตั้งและอัปเดตปลอม (Fake Installers & Updates)
        'update', 'setup', 'install', 'installer', 'flash', 'driver', 
        'codec', 'winrar', 'antivirus', 'cleaner',

        # 4. กลุ่มหลอกแจกของและกระตุ้นความอยากรู้ (Clickbait & Lures)
        'free', 'gift', 'prize', 'winner', 'bonus', 'leaked', 'private', 'secret', 'nude'
    ]
    
    file_name_lower = file_name.lower()
    score = 0
    
    for kw in keywords:
        # ปรับปรุง: ใช้ Regular Expression บังคับค้นหาแบบเต็มคำ หรือคั่นด้วยเครื่องหมายพิเศษอย่าง (_) (-) (.)
        # เพื่อไม่ให้ไปตรวจเจอคำย่อยที่ซ่อนอยู่ในชื่อฟังก์ชันหรือชื่อไฟล์ระบบที่ถูกต้อง
        pattern = rf'(?:^|[^a-z0-9]){re.escape(kw)}(?:[^a-z0-9]|$)'
        if re.search(pattern, file_name_lower):
            score += 1
            
    return score

def check_mismatch_flag(file_name, magic_bytes):
    """
    [ปรับปรุงเพิ่มมิติความหลากหลาย] ตรวจจับการปลอมแปลงนามสกุลไฟล์แบบสองทาง (Bidirectional Mismatch)
    เพิ่มการดักจับกรณีที่ไฟล์แจ้งว่าเป็นไฟล์ระบบแต่ไส้ในไม่ใช่ เพื่อป้องกันมัลแวร์หลุดรอด
    """
    if not isinstance(file_name, str) or not isinstance(magic_bytes, str):
        return 0

    ext = os.path.splitext(file_name.lower())[1]
    magic_lower = magic_bytes.lower()
    
    # คีย์เวิร์ดบ่งบอกประเภทหัวไฟล์ประมวลผลคำสั่งอันตราย
    is_executable_magic = any(kw in magic_lower for kw in ['executable', 'mach-o', 'dex', 'java class', 'shebang', 'shortcut'])
    is_archive_magic = any(kw in magic_lower for kw in ['zip', 'rar', '7-zip', 'gzip'])

    # 1. กลุ่มไฟล์รูปภาพ (.jpg, .jpeg, .png, .gif, .bmp)
    if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
        if is_executable_magic or is_archive_magic or any(kw in magic_lower for kw in ['pdf', 'office', 'rtf']):
            return 1
            
    # 2. กลุ่มไฟล์เอกสารทั่วไป (.pdf, .txt, .rtf)
    elif ext in ['.pdf', '.txt', '.rtf']:
        if is_executable_magic or is_archive_magic or 'image' in magic_lower:
            # ข้อยกเว้น: หากเป็นไฟล์สคริปต์ข้อความ .txt และหัวไฟล์เป็น Shebang ให้ยอมรับได้ แต่ถ้าเป็น .pdf หรือ .rtf ถือว่าปลอมแปลง
            if ext == '.txt' and 'shebang' in magic_lower:
                return 0
            return 1
            
    # 3. กลุ่มไฟล์ Microsoft Office (.doc, .docx, .xls, .xlsx)
    elif ext in ['.doc', '.docx', '.xls', '.xlsx']:
        # ไฟล์ Office ยุคใหม่มีโครงสร้างภายในเป็น ZIP Archive ดังนั้นจะตรวจจับเฉพาะเมื่อมีการซ่อนโค้ดรันระบบ (Executable) หรือปลอมข้ามตระกูลเป็น PDF เท่านั้น
        if is_executable_magic or 'pdf' in magic_lower:
            return 1
            
    # 4. กลุ่มไฟล์บีบอัด (.zip, .rar, .7z)
    elif ext in ['.zip', '.rar', '.7z']:
        if is_executable_magic:
            return 1

    # 5. กลุ่มไฟล์ประมวลผล/ระบบ (.exe, .dll, .sys, .scr, .cpl)
    elif ext in ['.exe', '.dll', '.sys', '.scr', '.cpl']:
        # หากชื่อไฟล์อ้างว่าเป็นไฟล์รันระบบ แต่ตรวจจับ Magic Bytes แล้วเป็นรูปภาพ, เอกสาร หรือเป็น Unknown Data แสดงว่าจงใจปลอมแปลงข้อมูลให้โมเดลสับสน
        if not is_executable_magic and not is_archive_magic and 'unknown' in magic_lower:
            return 1

    return 0

def get_basic_magic_bytes(file_data):
    """
    [ปรับปรุงเพิ่มความหลากหลายของชุดข้อมูล] ขยายฐานข้อมูลลายเซ็น Magic Bytes
    เพื่อให้ครอบคลุมช่องทางการโจมตีที่มักพบบ่อยบนระบบปฏิบัติการต่างๆ รวมถึงไฟล์ฝั่ง Linux
    """
    if not file_data:
        return "Unknown Data"
    
    # --- Executables, Binaries & Scripts ---
    if file_data.startswith(b'MZ'): return "PE executable for MS Windows"
    if file_data.startswith(b'\x7fELF'): return "ELF executable for Linux"
    if file_data.startswith(b'\xcf\xfa\xed\xfe') or file_data.startswith(b'\xce\xfa\xed\xfe') or file_data.startswith(b'\xfe\xed\xfa\xce'): return "Mach-O executable for macOS"
    if file_data.startswith(b'\xca\xfe\xba\xbe'): return "Compiled Java class file"
    if file_data.startswith(b'dex\n'): return "Dalvik dex file (Android)"
    if file_data.startswith(b'#!'): return "Script with Shebang (Bash/Python/etc.)"
    
    # [NEW] Linux specific archives and package managers
    if file_data.startswith(b'!<arch>'): return "ar archive (Linux .a / Debian .deb)"

    # เพิ่มการตรวจจับ Windows Shortcut (.lnk) ซึ่งเป็นเทคนิคพาหะที่มัลแวร์ยุคใหม่นิยมใช้รันสคริปต์เบื้องหลัง
    if file_data.startswith(b'\x4c\x00\x00\x00\x01\x14\x02\x00'): return "Windows Shortcut (.lnk)"

    # --- Archives & Compression ---
    if file_data.startswith(b'PK\x03\x04'): return "ZIP archive (or modern MS Office .docx/.xlsx)"
    if file_data.startswith(b'Rar!\x1a\x07'): return "RAR archive"
    if file_data.startswith(b'7z\xbc\xaf\x27\x1c'): return "7-zip archive"
    if file_data.startswith(b'\x1f\x8b'): return "GZIP compressed data"
    
    # [NEW] Common Linux compression formats (Often used for .tar.xz, .tar.bz2, etc.)
    if file_data.startswith(b'\xfd7zXZ\x00'): return "XZ compressed data"
    if file_data.startswith(b'BZh'): return "Bzip2 compressed data"
    if file_data.startswith(b'\x28\xB5\x2F\xFD'): return "Zstandard compressed data"
    if file_data.startswith(b'\x04\x22\x4d\x18'): return "LZ4 compressed data"

    # --- Documents ---
    if file_data.startswith(b'%PDF-'): return "PDF document"
    if file_data.startswith(b'\xd0\xcf\x11\xe0'): return "Legacy MS Office document (.doc/.xls) or MSI Installer"
    if file_data.startswith(b'{\\rtf1'): return "Rich Text Format (RTF)"

    # --- Images ---
    if file_data.startswith(b'\xff\xd8\xff'): return "JPEG image"
    if file_data.startswith(b'\x89PNG\r\n\x1a\n'): return "PNG image"
    if file_data.startswith(b'GIF87a') or file_data.startswith(b'GIF89a'): return "GIF image"
    if file_data.startswith(b'BM'): return "BMP image data"
    
    # เพิ่มการดักจับสคริปต์เว็บ/ไฟล์แฝงคำสั่งที่มักใช้นามสกุลลวง (HTML/HTA)
    file_data_upper = file_data[:50].upper()
    if b'<HTML' in file_data_upper or b'<!DOCTYPE HTML' in file_data_upper:
        return "HTML document / Web page"

    return "Unknown Data"

def calculate_shannon_entropy(file_data):
    """
    Optimized Shannon Entropy calculation.
    Caps the data at 512KB to significantly improve CPU speed without losing accuracy.
    """
    data_to_analyze = file_data[:512 * 1024]  # ลดเหลือ 512 KB
    
    if not data_to_analyze:
        return 0.0
        
    counts = Counter(data_to_analyze)
    length = len(data_to_analyze)
    
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
        
    return entropy

# ==========================================
# 2. Worker & Processing
# ==========================================
def process_file_data(task_args):
    fp, size, threat_level, db_path, existing_hashes = task_args
    try:
        file_name = os.path.basename(fp)
        ext = os.path.splitext(file_name.lower())[1]
        
        if file_name == os.path.basename(db_path):
            return None
            
        with open(fp, 'rb') as f:
            file_data = f.read()
            
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        if sha256_hash in existing_hashes:
            return None
            
        if size <= 10 * 1024 * 1024:
            ssdeep_hash = ppdeep.hash(file_data)
        else:
            # ถ้าไฟล์ใหญ่เกินไป ให้ทำ Fuzzy hash แค่ 2MB แรกแทน
            ssdeep_hash = ppdeep.hash(file_data[:2 * 1024 * 1024])
            
        if not ssdeep_hash: return None

        # ตอนนี้ Entropy ของเราเร็วขึ้นและโดน Cap ไว้ที่ 2MB แล้วในตัวฟังก์ชัน
        file_entropy = calculate_shannon_entropy(file_data)
        magic_bytes = get_basic_magic_bytes(file_data)
        
        # [UPDATE] เพิ่มลอจิกคัดแยก Android, Windows และขยายการรองรับ Linux
        # ครอบคลุม Ubuntu, Debian, Mint (.deb, snap, appimage, bash scripts)
        is_linux_script = False
        if file_data.startswith(b'#!'):
            head = file_data[:50].lower()
            if b'bin/sh' in head or b'bin/bash' in head or b'usr/bin/env' in head:
                is_linux_script = True

        if ext == '.apk' or file_data.startswith(b'dex\n'):
            os_target = "Android"
        elif file_data.startswith(b'MZ'):
            os_target = "Windows"
        elif (file_data.startswith(b'\x7fELF') or 
              ext in ['.deb', '.snap', '.appimage'] or 
              file_data.startswith(b'!<arch>') or 
              is_linux_script):
            os_target = "Linux"
        else:
            os_target = "Other"

        features = {
            'sha256': sha256_hash,
            'file_name': file_name,
            'file_size_bytes': size,
            'magic_bytes': magic_bytes,
            'block_size': int(ssdeep_hash.split(':')[0]) if ':' in ssdeep_hash else size,
            'ssdeep_full': ssdeep_hash,
            'file_entropy': file_entropy,
            'imphash': 'None',
            'os': os_target,
            'feat_double_ext': detect_double_extension(file_name),
            'feat_susp_score': calculate_suspicious_score(file_name),
            'feat_mismatch': check_mismatch_flag(file_name, magic_bytes),
            'num_sections': 0,
            'threat': threat_level
        }
        
        # --- Deep Scan: Windows PE ---
        if features['os'] == 'Windows':
            # [OPTIMIZATION 4] ป้องกัน pefile พยายามอ่านไฟล์แปลกประหลาดที่ใหญ่เกิน 20MB
            if size <= 20 * 1024 * 1024:
                try:
                    pe = pefile.PE(data=file_data, fast_load=True)
                    features['num_sections'] = len(pe.sections)
                    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                    features['imphash'] = pe.get_imphash() or 'None'
                    pe.close()
                except Exception: # เปลี่ยนจาก pefile.PEFormatError เป็น Exception ทั่วไปกันเหนียว
                    pass
        # --- Deep Scan: Linux ELF ---
        elif features['os'] == 'Linux':
            try:
                elf = ELFFile(io.BytesIO(file_data))
                features['num_sections'] = elf.num_sections()
                dynamic_segment = elf.get_section_by_name('.dynamic')
                if dynamic_segment:
                    imports = [tag.needed for tag in dynamic_segment.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']
                    if imports:
                        import_str = ",".join(sorted(imports))
                        features['imphash'] = hashlib.md5(import_str.encode()).hexdigest()
            except Exception:
                pass

        # --- [NEW] Deep Scan: Android APK / DEX ---
        elif features['os'] == 'Android':
            try:
                # กรณีที่ 1: เป็นไฟล์แอปพลิเคชันสำเร็จรูป (.apk)
                if file_data.startswith(b'PK\x03\x04') and ext == '.apk':
                    with zipfile.ZipFile(io.BytesIO(file_data)) as apk:
                        namelist = apk.namelist()
                        # num_sections = จำนวนไฟล์ทั้งหมดที่แพ็ครวมอยู่ภายใน APK
                        features['num_sections'] = len(namelist)
                        
                        # Asset/Structure Hash = นำโครงสร้างและรายชื่อไฟล์มาเรียงลำดับเพื่อทำแฮชจำลอง ImpHash
                        layout_str = ",".join(sorted(namelist))
                        features['imphash'] = hashlib.md5(layout_str.encode()).hexdigest()
                        
                # กรณีที่ 2: เป็นไฟล์โค้ดดิบ (.dex)
                elif file_data.startswith(b'dex\n') and len(file_data) > 0x64:
                    # เจาะไปที่ Offset 0x60 เพื่อดึงขนาด Class IDs Size (4 bytes uint) จาก DEX Header
                    class_ids_size = struct.unpack('<I', file_data[0x60:0x64])[0]
                    features['num_sections'] = class_ids_size
                    features['imphash'] = 'None'
            except Exception:
                pass
                
        return features
    except Exception:
        return None


def get_files_fast(target_dir, limit, max_size):
    """
    Super Optimized Scanner (Stack + os.scandir).
    Filters necessary extensions strictly by name BEFORE touching Disk I/O.
    """
    valid_files = []
    stack = [os.path.normpath(target_dir)]
    
    STANDARD_EXTS = {
        '.exe', '.dll', '.sys', '.scr', '.pif', '.cpl', '.com', '.elf', '.bin', '.apk', '.dex',
        '.py', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.sh', '.wsf', '.hta', '.jar'
    }
    
    print("[*] Starting fast directory scan (this may take a moment)...")
    
    while stack and len(valid_files) < limit:
        current_dir = stack.pop()
        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    if len(valid_files) >= limit:
                        break
                        
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                        
                    elif entry.is_file(follow_symlinks=False):
                        name_lower = entry.name.lower()
                        is_target_file = False
                        
                        # [STRATEGY 1] เช็กจากคำค้นในชื่อไฟล์
                        if any(keyword in name_lower for keyword in ['.msil.', '.win.', '.linux.', '.elf.', '.apk.', '.python.', '.php.', '.asp.', '.script.']):
                            is_target_file = True
                            
                        # [STRATEGY 2] เช็กนามสกุลปกติ
                        else:
                            ext = os.path.splitext(name_lower)[1]
                            if ext in STANDARD_EXTS:
                                is_target_file = True
                        
                        # [STRATEGY 3] OPTIMIZED: แอบอ่าน 4 ไบต์แรก "เฉพาะไฟล์ที่ไม่มีนามสกุล" เท่านั้น! 
                        # (ลด Disk I/O ไปได้มากกว่า 99% ทำให้โปรแกรมไม่ค้าง)
                        if not is_target_file and not ext: 
                            try:
                                with open(entry.path, 'rb') as f:
                                        magic = f.read(4)
                                        if magic.startswith(b'MZ') or magic.startswith(b'\x7fELF') or magic.startswith(b'PK\x03\x04'):
                                            is_target_file = True
                            except OSError:
                                continue
                                
                        if not is_target_file:
                            continue
                            
                        try:
                            size = entry.stat().st_size
                            if size <= max_size:
                                valid_files.append((entry.path, size))
                                # โชว์สถานะให้รู้ว่าโปรแกรมไม่ได้ค้าง ทุกๆ การเจอ 500 ไฟล์
                                if len(valid_files) % 500 == 0:
                                    sys.stdout.write(f"\r[*] Scanning... Found {len(valid_files)} matching files so far.")
                                    sys.stdout.flush()
                        except OSError:
                            continue
        except OSError:
            continue
            
    sys.stdout.write(f"\r[*] Scanning complete! Total matching files found: {len(valid_files)}     \n")
    sys.stdout.flush()
    return valid_files