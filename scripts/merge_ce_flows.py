import glob
import os

import pandas as pd


def merge_and_sort_ce_flows(input_dir: str, output_file: str):
    # Expand input directory and get all CSV files
    csv_files = glob.glob(os.path.join(input_dir, '*.csv'))

    if not csv_files:
        print(f'No CSV files found in {input_dir}')
        return

    dataframes = []
    for file in csv_files:
        try:
            df = pd.read_csv(file, parse_dates=['timestamp'])
            dataframes.append(df)
        except Exception as e:
            print(f'Failed to process {file}: {e}')

    if not dataframes:
        print('No valid dataframes were loaded.')
        return

    # Concatenate all dataframes
    merged_df = pd.concat(dataframes, ignore_index=True)

    # Sort by timestamp descending (newest first)
    merged_df = merged_df.sort_values(by='timestamp', ascending=False)

    # Save to CSV
    merged_df.to_csv(output_file, index=False)
    print(f'Merged file saved to {output_file}')


if __name__ == '__main__':
    input_dir = './CEFlows'
    output_file = os.path.join(input_dir, 'merged_CE_flows.csv')
    merge_and_sort_ce_flows(input_dir, output_file)
