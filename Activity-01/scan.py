from pathlib import Path
import argparse
import csv

def scan_files(directory, extension):
    directory = Path(directory)
    if not directory.exists():
        print("Directory does not exist.")
        return

    pattern = f"*.{extension.lstrip('.')}"
    matched_files = list(directory.rglob(pattern))

    print(f"\nScanning: {directory.resolve()}")
    print(f"Found {len(matched_files)} '.{extension}' files:\n")

    print(f"{'File':<40} {'Size (KB)':>10}")
    print("-" * 52)

    results = []
    total_size = 0
    for file in matched_files:
        size_kb = file.stat().st_size / 1024
        total_size += size_kb
        relative_path = str(file.relative_to(directory))
        results.append((relative_path, round(size_kb, 1)))
        print(f"{relative_path:<40} {size_kb:>10.1f}")

    print("-" * 52)
    print(f"Total size: {total_size:.1f} KB\n")

    # Write to CSV
    output_csv = Path("output.csv")
    with output_csv.open("w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["file", "size_kb"])
        for row in results:
            writer.writerow(row)

    print(f"Results written to: {output_csv.resolve()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursively scan directory for files.")
    parser.add_argument("path", help="Path to directory to scan")
    parser.add_argument("--ext", default="txt", help="File extension to scan for (default: txt)")
    args = parser.parse_args()

    scan_files(args.path, args.ext)
