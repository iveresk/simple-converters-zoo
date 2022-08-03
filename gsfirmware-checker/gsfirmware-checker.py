import csv
import argparse
import os
import requests


def printtable(firmware, regime, output):
    if output == "console":
        if len(firmware) < 3:
            print(firmware)
            return
        if regime == "1":
            print("-"*33 + "-Table-of-versions-" + "-"*33)
            for i in range(1, len(firmware)-1, 3):
                print("| " + firmware[i-1] + " | " + firmware[i] + " | " + firmware[i+1] + " |")
                print("-" * 85)
        if regime == "2":
            print("-"*20 + "-Table-of-CVEs-" + "-"*20)
            for i in range(1, len(firmware)-1, 2):
                print("| " + firmware[i-1] + " | " + firmware[i] + " | ")
                print("-" * 50)
    elif output == "file":
        try:
            with open("output", "r") as f:
                lines = f.readlines()
        except:
            lines = []
        # adding scan results to the file

        try:
            with open("scan1.csv", "r") as sf:
                slines = sf.readlines()
        except:
            print("Scan file is damaged. Can not transfer it to the Output report file")
            sf.close()
        sf.close()
        lines.append(slines)
        # main checks are on the flight
        if len(firmware) < 3:
            lines.append(firmware)
            return
        if regime == "1":
            lines.append("-"*33 + "-Table-of-versions-" + "-"*33)
            for i in range(1, len(firmware)-1, 3):
                lines.append("| " + firmware[i-1] + " | " + firmware[i] + " | " + firmware[i+1] + " |")
                lines.append("-" * 85)
        if regime == "2":
            lines.append("-"*20 + "-Table-of-CVEs-" + "-"*20)
            for i in range(1, len(firmware)-1, 2):
                lines.append("| " + firmware[i-1] + " | " + firmware[i] + " | ")
                lines.append("-" * 50)
        try:
            with open("output", "w+") as f:
                for line in lines:
                    content = str(line)
                    # checks if we need a '\n' = new line symbol for the line
                    # otherwise it will add a new line for every scanned IP
                    if len(content.split("\n")) == 1:
                        content = content + "\n"
                    f.writelines(content)
        except:
            f.close()
        f.close()



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
    for i in range(0, len(etalon)-1, 2):
        for j in range(0, len(scan)):
            index = scan[j].split(" ")
            for k in range(1, len(index)):
                if index[k] == '':
                    break
                if index[k] in etalon[i] or etalon[i] in index[k]:
                    report.append(scan[j-1])
                    report.append(scan[j])
                    version = etalon[i+1].split(";")
                    report.append(version[1])
                    break
    return report


def csvparser(regime, csvfile):
    res = []
    try:
        file = open(csvfile)
        csvreader = csv.reader(file)
    except:
        print("Can not open file " + csvfile)
        file.close()
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
    else:
        for row in rows:
            for col in row:
                if col in '':
                    continue
                if col in 'N/A':
                    continue
                res.append(col)
    file.close()
    return res


def main(gcsvfile, checkip, system, output):
    etalon = csvparser("etalon", gcsvfile)
    if system == "kali":
        os.system("svreport delete -t svmap -s scan1")
        cmd = "svmap -s scan1 " + checkip
        cmd1 = "svreport export -f csv -o scan1.csv -t svmap -s scan1"
    else:
        os.system("sipvicious_svreport delete -t svmap -s scan1")
        cmd = "sipvicious_svmap -s scan1 " + checkip
        cmd1 = "sipvicious_svreport export -f csv -o scan1.csv -t svmap -s scan1"
    os.system(cmd)
    os.system(cmd1)
    scan = csvparser("scan", "scan1.csv")
    # checking firmware
    firmware = checkfirmware(etalon, scan)
    if firmware == []:
        return
    printtable(firmware, "1", output)
    # CSV CVE Base
    csvbase = csvparser("cvebase", "gscvebase.csv")
    # transform versions
    firmware_transformed = transformversions(firmware)
    base_transformed = transformversions(csvbase)
    # Calculate versions
    report = calculateversions(firmware_transformed, base_transformed)
    if report != []:
        printtable(report, "2", output)
    # checking for default passwords



if __name__ == '__main__':
    # default parameters
    system = "kali"
    regime = "console"
    # parsing input
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--versions', type=str, required=True)
    parser.add_argument('-i', '--ip', type=str, required=True)
    parser.add_argument('-s', '--system', type=str, required=False)
    parser.add_argument('-o', '--output', type=str, required=False)
    args = parser.parse_args()
    # if system -s key exists we are overwriting the default value
    if args.system is not None:
        system = args.system
    # if regime -r key exists we are overwriting the default value
    if args.output is not None:
        if args.output == "console" or args.output == "file":
            regime = args.output
        else:
            print("-r or --regime parameter should be 'console' or 'file'")
            exit(0)

    # checking if we are working with IP or file
    if os.path.exists(args.ip):
        # checking the file for valid format
        try:
            file = open(args.ip)
            ips = file.readlines()
        except:
            print("The file format isn't valid")
            exit(0)
        for row in ips:
            # clearing ip from '\n' symbol
            ip = row.split("\n")
            main(args.versions, ip[0], system, regime)
    else:
        main(args.versions, args.ip, system, regime)
