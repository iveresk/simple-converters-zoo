import argparse
import re
from bs4 import BeautifulSoup


def writetargets(filename, content):
    f = open(filename, 'w', encoding="utf-8")
    for item in content:
        f.write(f'{item}\n')
    f.close()


def readtargets(filename):
    with open(filename) as f:
        lines = f.readlines()
    f.close()
    return lines


def findips(target):
    result = []
    with open("firepower_windows_hosts.html") as fp:
        soup = BeautifulSoup(fp, 'html.parser')
    trtags = soup.find_all('tr')
    wins = readtargets(target)
    for line in wins:
        ip = re.search(re.compile('([0-9]{1,3}\.){3}([0-9]{1,3})'), line)[0]
        for tr in trtags:
            foundip = False
            foundwin = False
            for td in tr:
                if re.search(re.compile(ip), td.string) is not None:
                    foundip = True
                if re.search('Microsoft', td.string) is not None or re.search('Windows', td.string) is not None:
                    foundwin = True
            if foundip and foundwin:
                result.append(ip)
                break
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', type=str, required=False)
    parser.add_argument('-o', '--output', type=str, required=False)
    args = parser.parse_args()
    if args.target is None:
        args.target = "firepower_new_hosts_24h.txt"
    result = findips(args.target)
    if args.output is None:
        for item in result:
            print(f'{item}')
    else:
        writetargets(args.output, result)
