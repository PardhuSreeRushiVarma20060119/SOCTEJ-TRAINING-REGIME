import subprocess
import os
import argparse

def run_volatility(memory_file, plugin, output_dir):
    print(f"[*] Running Volatility plugin: {plugin} on {memory_file}")
    output_file = os.path.join(output_dir, f"{plugin}.txt")
    
    # Simple command for Volatility 3
    cmd = ["python3", "vol.py", "-f", memory_file, f"windows.{plugin}"]
    
    try:
        with open(output_file, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, check=True)
        print(f"[+] Output saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running plugin {plugin}: {e.stderr.decode()}")

def main():
    parser = argparse.ArgumentParser(description="Automate Volatility 3 plugins for memory analysis.")
    parser.add_argument("memory_file", help="Path to the memory image file")
    parser.add_argument("--outdir", default="volatility_reports", help="Directory to save reports")
    args = parser.parse_args()

    if not os.path.exists(args.outdir):
        os.makedirs(args.outdir)

    plugins = ["pslist", "pstree", "netscan", "malfind", "cmdline"]
    
    for plugin in plugins:
        run_volatility(args.memory_file, plugin, args.outdir)

if __name__ == "__main__":
    main()
