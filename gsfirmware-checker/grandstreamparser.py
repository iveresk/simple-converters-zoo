import csv
import argparse
import os


def printtable(firmware, regime):
    if len(firmware) < 3:
        print(firmware)
        return
    if regime == 1:
        for i in range(1, len(firmware)-1, 3):
            print("-"*30 + "-Table-of-versions-" + "-"*30)
            print("| " + firmware[i-1] + " | " + firmware[i] + " | " + firmware[i+1] + " |")
            print("-" * 70)
    if regime == 2:
        for i in range(1, len(firmware)-1, 4):
            print("-"*20 + "-Table-of-CVEs-" + "-"*20)
            print("| " + firmware[i-1] + " | " + firmware[i] + " | ")
            print("-" * 50)
            print("| " + firmware[i+1] + " |" + firmware[i+2] + " |")
            print("-" * 50)


def calculateversions(firmware, basecve):
    res = []
    for i in range(0, len(firmware), 2):
        firmwarespace = firmware[i].split(" ")
        for j in range(0, len(basecve), 2):
            basespace = basecve[j].split(";")
            if firmwarespace[0] in basespace[1]:
                if firmware[i+1] <= basecve[j+1]:
                    res.append(firmware[i])
                    res.append(basespace[0])
    return res


def versiontoint(totransform):
    res = ""
    temp = 0
    if "1." in totransform:
        try:
            index1 = totransform.split("1.")
            index2 = "1." + index1[1]
            index = index2.split(".")
            for i in range(0, len(index)):
                if index[0] == "1":
                    r = index[i].split(" ")
                    if len(r) > 1:
                        res = res + r[0]
                        int(res)
                        temp = int(res)
                        continue
                    res = res + index[i]
                    int(res)
                    temp = int(res)
                if index[1] == "1":
                    if len(r) > 1:
                        res = res + r[0]
                        int(res)
                        temp = int(res)
                        continue
                    res = res + index[i]
                    int(res)
                    temp = int(res)
        except:
            return temp
    return temp


def transformversions(totransform):
    report = []
    lentamente = len(totransform)
    if lentamente <= 1:
        temp = versiontoint(totransform)
        totransform.append(temp)
    else:
        for i, row in enumerate(totransform):
            if i >= lentamente:
                break
            if "1." in row:
                temp = versiontoint(row)
                report.append(row)
                report.append(temp)
    return report


def checkfirmware(etalon, scan):
    report = []
    for i in range(0, len(etalon)):
        for j in range(1, len(scan)):
            index = scan[j].split(" ")
            for k in range(0, len(index)):
                if index[k] in etalon[i] or etalon[i] in index[k]:
                    report.append(scan[j-1])
                    report.append(scan[j])
                    version = etalon[i+1].split(";")
                    report.append(version[1])
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
                if "PBX" in col or "TP-Link" in col:
                    res.append(col)

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
    printtable(firmware, 1)
    # TODO CSV CVE Base
    csvbase = csvparser("cvebase", "gscvebase.csv")
    # TODO transform versions
    firmware_transformed = transformversions(firmware)
    base_transformed = transformversions(csvbase)
    # TODO Calculate versions
    report = calculateversions(firmware_transformed, base_transformed)
    printtable(report, 2)


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
