import gathering as gather
import management as manage
import cleaning
import eda
import model_training as train
import evaluation as eval
import sys
import os

# --- Database path ---
DB_PATH = "malware_analytics.db"

# --- Whitelist of target extensions ---
TARGET_EXTENSIONS = {
    # === 1. Windows Executables & Libraries (เพิ่ม MSI, OCX, DRV) ===
    '.exe', '.dll', '.sys', '.scr', '.pif', '.cpl', '.com', 
    '.msi', '.ocx', '.drv',

    # === 2. Linux & macOS ===
    '.elf', '.bin', '.sh', 
    '.macho', '.dylib',

    # === 3. Android ===
    '.apk', '.dex',

    # === 4. Scripts, Java & Interpreted (เพิ่ม Python, VBA) ===
    '.bat', '.cmd', '.vbs', '.vbe', '.ps1', '.wsf', '.hta', '.js', '.jar', 
    '.py', '.pyc', '.vba', '.pl',

    # === 5. Office Documents & PDF (Phishing & Macro Malware) ===
    '.doc', '.docx', '.docm',  # Word
    '.xls', '.xlsx', '.xlsm',  # Excel
    '.ppt', '.pptx', '.pptm',  # PowerPoint
    '.rtf', '.pdf',

    # === 6. Archives & Disk Images (Dropper) ===
    '.zip', '.rar', '.7z', '.tar', '.gz', 
    '.cab', '.iso', '.img'
}

# --- Banner ---
def print_banner():
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    banner = r"""
 __  __           _        _           
|  \/  | ___   __| | ___  | |
| |\/| |/ _ \ / _` |/ _  \| | 
| |  | | (_) | (_| | (-__) | |_ 
|_|  |_|\___/ \__,_|\___/ \__|

""" + f"""{GREEN}                       
      (\\__/)
      ( •_•)   {YELLOW}Model Training{RESET}
      / >🕷             by So secure
"""
    print(CYAN + banner + RESET)


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def main_menu():
    while True:
        print_banner()
        print("\n=== Main Menu ===")
        print("1. Data Gathering")
        print("2. Database Management")
        print("3. EDA/Model Training")
        print("4. Evaluation")
        print("5. Exit")
        
        choice = input("Select an option (1-5): ").strip()
        
        if choice == '1':
            clear_screen()
            gather.Data_gathering()

        elif choice == '2':
            clear_screen()
            print("\n=== Malware Database Utility ===")
            print("1. Merge Databases")
            print("2. Clean Database")
            choice = input("\nเลือกเมนู (1/2): ").strip()
            if choice == "1":
                main_db = input("กรอกชื่อไฟล์ฐานข้อมูลหลัก: ").strip()
                sources = input("กรอกชื่อฐานข้อมูลที่จะ merge (คั่นด้วย ,): ").strip().split(",")
                manage.merge_sqlite_databases(main_db, sources)
            elif choice == "2":
                db_path = input("กรอกชื่อไฟล์ฐานข้อมูล: ").strip()
                target_exts = [".exe", ".dll", ".elf", ".apk"]
                manage.clean_database(db_path, target_exts)
            else:
                print("[-] ไม่พบเมนูที่เลือก")

        elif choice == '3':
            clear_screen()
            print("\n=== Model Training ===")
            print("1. Train Model")
            print("2. EDA (Exploratory Data Analysis)")
            print("3. Clean Data")
            choice = input("\nเลือกเมนู (1/2/3): ").strip()
            if choice == "1":
                train.model_train_optimized()
            elif choice == "2":
                eda.malware_eda()
            elif choice == "3":
                cleaning.clean_and_save()
            else:
                print("[-] ไม่พบเมนูที่เลือก")

        elif choice == '4':
            clear_screen()
            print("\n=== Evaluation ===")
            eval.run_evaluation()

        elif choice == '5':
            print("Goodbye!")
            sys.exit(0)

        else:
            print("[!] Invalid choice, please try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main_menu()
