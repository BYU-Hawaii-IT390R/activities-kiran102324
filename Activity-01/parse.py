import argparse

parser = argparse.ArgumentParser(description="A file parser")
parser.add_argument('--input', type=str, help="Path to input file")
parser.add_argument('--output', type=str, help="Path to output file")

args = parser.parse_args()