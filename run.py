import sys
import os
import subprocess



def print_banner():
    print("========================================")
    print("       MALWARE ANALYZER")
    print("          Unhashers       ")
    print("========================================")


def main():
    while True:
        print_banner()
        print("1. Start Web Server (Recommended)")
        print("2. Run Interactive CLI Analysis")
        print("3. Exit")
        print("========================================")
        
        choice = input("Enter choice [1]: ").strip().lower()
        
        if choice == '1' or choice == '':
            print("\n[+] Starting Web Server on http://127.0.0.1:5000 ...")
            try:
                subprocess.run([sys.executable, "-m", "malware_analyzer.app"])
            except KeyboardInterrupt:
                print("\n[!] Server stopped.")
            
        elif choice == '2':
            target = input("\nEnter file path to analyze (or 'back' to return): ").strip()
            if target.lower() == 'back':
                continue
                
            if target:
                # remove quotes if user copied path as "path"
                target = target.strip('"\'')
                if os.path.exists(target):
                    print(f"\n[+] Analyzing: {target} ...")
                    subprocess.run([sys.executable, "-m", "malware_analyzer.cli", target])
                    print("\n[+] Analysis complete. Check 'reports/' folder.")
                    input("\nPress Enter to continue...")
                else:
                    print(f"\n[-] Error: File not found: {target}")
                    input("\nPress Enter to continue...")
            else:
                print("[-] No file specified.")
                
        elif choice == '3' or choice == 'q':
            print("Goodbye!")
            sys.exit(0)
        else:
            print("[-] Invalid choice.")
            input("Press Enter to continue...")


if __name__ == "__main__":
    main()
