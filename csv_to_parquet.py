import pandas as pd
import argparse

parser = argparse.ArgumentParser(description="parses argument for csv to parquet converter", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument("-csv", help="Name of file to be converted in parquet")
parser.add_argument("-parquet", help="name of parquet file to be created")

args = parser.parse_args()
config = vars(args)

csv_filename = config['csv']
parquet_filename = config['parquet']

input_file = pd.read_csv(csv_filename)
input_file.to_parquet(parquet_filename)

