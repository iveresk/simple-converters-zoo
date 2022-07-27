import csv
import argparse
import os


def printtable(firmware):
    if len(firmware) <= 3:
        print(firmware)
        return
    for i in range(1, len(firmware)-1, 3):
        print("-"*60)
        print("| " + firmware[i-1] + " | " + firmware[i] + " | " + firmware[i+1] + " |")


def checkfirmware(etalon, scan):
    report = []
    for i in range(0, len(etalon)):
        for j in range(1, len(scan)):
            if scan[j] in etalon[i] or etalon[i] in scan[j]:
                report.append(scan[j-1])
                report.append(scan[j])
                version = etalon[i+1].split(" ")
                report.append(version[0])
    return report


def csvparser(regime, csvfile):
    res = []
    file = open(csvfile)
    csvreader = csv.reader(file)
    rows = []
    for row in csvreader:
        rows.append(row)

    if regime in "etalon":
        for row in rows:
            for col in row:
                if col == '':
                    continue
                if "GWN" in col or "UCM" in col or "GRP" in col or "GXP" in col or "WP" in col or "DP" in col:
                    res.append(col)
                if "GVC" in col or "IPVT" in col or "GMD" in col or "GAC" in col or "GXV" in col or "GBX" in col:
                    res.append(col)
                if "HT" in col or "GXW" in col or "GSC" in col or "GDS" in col or "BT" in col or "GXP" in col:
                    res.append(col)
                if "PBX":
                    res.append(col)
                if "1." in col:
                    index = col.split(" ")
                    res.append(index[0])

    else:
        for row in rows:
            for col in row:
                if col in '':
                    continue
                if col in 'N/A':
                    continue
                res.append(col)
    return res


def main(gcsvfile, checkip, system):
    etalon = csvparser("etalon", gcsvfile)
    if system == "kali":
        os.system("svreport delete -t svmap -s scan1")
        cmd = "svmap -s scan1 " + checkip + " && svreport export -f csv -o scan1.csv -t svmap -s scan1"
    else:
        os.system("sipvicious_svreport delete -t svmap -s scan1")
        cmd = "sipvicious_svmap -s scan1 " + checkip + " && sipvicious_svreport export -f csv -o scan1.csv -t svmap -s scan1"
    os.system(cmd)
    scan = csvparser("scan", "scan1.csv")
    # TODO checking firmware
    firmware = checkfirmware(etalon, scan)
    printtable(firmware)
    # TODO JSON CVE Base

    # TODO reportcsv(etalon, scan, cvejson)


if __name__ == '__main__':
    system = "kali"
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--versions', type=str, required=True)
    parser.add_argument('-i', '--ip', type=str, required=True)
    parser.add_argument('-s', '--system', type=str, required=False)
    args = parser.parse_args()
    if args.system is not None:
        system = args.system
    main(args.versions, args.ip, system)
