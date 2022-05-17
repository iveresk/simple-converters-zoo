import xmltodict
import pandas as pd
import argparse


def main(xmlfile, csvfile):
    f = open(xmlfile, "r")
    xml = f.read()
    df = pd.DataFrame(xmltodict.parse(str(xml)))
    df.rename(columns=lambda x: x.replace('@', ''), inplace=True)
    df.to_csv(csvfile)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=argparse.FileType(), nargs='+')
    args = parser.parse_args()
    if args is None:
        print("\n To launch the code you should stick to the next format:")
        print("python3 xmltocsv.py <xml_filename> <csv_filename>")
    main(args.file[0], args.file[1])
