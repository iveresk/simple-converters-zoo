from censys.search import CensysHosts
import re
import argparse


def main(query, pages):
    h = CensysHosts()
    output_file = open("output.txt", "w")
    for page in h.search(query, per_page=100, pages=pages):
        ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(page))
        for ip in ips:
            output_file.write(str(ip)+"\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--query', type=str, required=True)
    parser.add_argument('-p', '--pages', type=int, required=False)
    args = parser.parse_args()
    if args.pages is None:
        main(args.query, 1)
    else:
        main(args.query, args.pages)