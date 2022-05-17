import xmltodict
import pandas as pd
import argparse


def main(xmlfile, csvfile):
    with xmlfile as f:
        xml = f.read()
    df = pd.DataFrame(xmltodict.parse(str(xml)))
    df.rename(columns=lambda x: x.replace('@', ''), inplace=True)
    df.to_csv(csvfile)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--xml", "-x", type=str, required=True)
    parser.add_argument("--csv", "-c", type=str, required=True)
    args = parser.parse_args()
    main(args.xml, args.csv)
