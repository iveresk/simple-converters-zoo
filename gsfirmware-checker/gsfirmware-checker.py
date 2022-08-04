import csv
import argparse
import os
import time
import random
import requests


def printtable(firmware, regime, output):
    if output == "console":
        # quick report for non-standart cases
        if len(firmware) < 3:
            print(firmware)
            return
        # report for the -Table-of-versions- compare
        if regime == "1":
            print("-"*33 + "-Table-of-versions-" + "-"*33)
            for i in range(1, len(firmware)-1, 3):
                print("| " + firmware[i-1] + " | " + firmware[i] + " | " + firmware[i+1] + " |")
                print("-" * 85)
        # report for the -Table-of-CVEs- compare
        if regime == "2":
            print("-"*20 + "-Table-of-CVEs-" + "-"*20)
            for i in range(1, len(firmware)-1, 2):
                print("| " + firmware[i-1] + " | " + firmware[i] + " | ")
                print("-" * 50)
        # report for the -Weak-Passwords-
        if regime == "3":
            print("-"*14 + "-Weak-Passwords-" + "-"*15)
            for i in range(1, len(firmware)-1, 4):
                print("| " + firmware[i-1] + " | " + firmware[i] + " | " + firmware[i+1] + " | " + firmware[i+2] + " |")
                print("-" * 45)
    # the same regimes but for file output
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
        if regime == "3":
            lines.append("-"*20 + "-Weak-Passwords-" + "-"*20)
            for i in range(1, len(firmware)-1, 4):
                lines.append("| " + firmware[i-1] + " | " + firmware[i] + " | " + firmware[i+1] + " | " + firmware[i+2])
                lines.append("-" * 60)
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
    for i in range(0, len(etalon)-1):
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


def parsevoips(scans):
    res = []
    bytefree = []
    for i in range(0, len(scans)):
        bytefree.append(scans[i].split("b'")[1])
    for i in range(1, len(bytefree), 2):
        res.append(bytefree[i].split(" ")[0])
        res.append(bytefree[i-1].split(":")[0])
    return res


def getGSsession():
    # Session should be randomly generated where the 10th symbol is 'e'
    rand = ""
    for i in range(0, 20):
        if i == 9:
            rand = rand + "e"
            continue
        rand = rand + str(random.randint(0, 9))
    cookies = {'session-role': 'user', 'session-identity': rand}
    return cookies


def prepareGSheader(targetip):
    url = "http://" + targetip + "/cgi-bin/dologin"
    headers = {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate', 'Accept-Language': 'en-US,en;q=0.5', 'Cache-Control': 'max-age=0, no-cache', 'Connection': 'keep-alive', 'Content-Length': '26', 'Content-Type': 'application/x-www-form-urlencoded', 'Host': targetip, 'Origin': 'http://'+ targetip, 'Pragma': 'no-cache', 'Referer': 'http://'+ targetip, 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'}
    cookies = getGSsession()
    return url, headers, cookies


def checkdefaultpasswords(parsedvoips):
    vulns = []
    # default passwords for the Grandstreams
    defaultpasses = {'Grandstream': ['admin', 'admin', 'user', '123']}
    for i in range(0, len(parsedvoips), 2):
        if "Grandstream" in parsedvoips[i]:
            # requesting main params for the request
            url, headers, cookies = prepareGSheader(parsedvoips[i+1])
            for j in range(0, len(defaultpasses['Grandstream']), 2):
                r = requests.post(url, data={'username': defaultpasses['Grandstream'][j], 'password': defaultpasses['Grandstream'][j+1]}, headers=headers, cookies=cookies)
                try:
                    # if we used all attempts we are sleeping for 5 mins and 1 sec and trying one more request
                    if "locked" in r.json()['body']:
                        time.sleep(301)
                        r = requests.post(url, data={'username': defaultpasses['Grandstream'][j],
                                                     'password': defaultpasses['Grandstream'][j + 1]}, headers=headers,
                                          cookies=cookies)
                    # if we've logged in - we are saving the username and password for the report
                    if "wrong" not in r.json()['body']:
                        vulns.append(parsedvoips[i])
                        vulns.append(parsedvoips[i+1])
                        vulns.append(defaultpasses['Grandstream'][j])
                        vulns.append(defaultpasses['Grandstream'][j+1])
                except:
                    break
                time.sleep(1)
    return vulns

def main(gcsvfile, checkip, system, output):
    # parsing firmwares
    etalon = csvparser("etalon", gcsvfile)
    # checking what system we received from the command line
    if system == "kali":
        os.system("svreport delete -t svmap -s scan1")
        cmd = "svmap -s scan1 " + checkip
        cmd1 = "svreport export -f csv -o scan1.csv -t svmap -s scan1"
    else:
        os.system("sipvicious_svreport delete -t svmap -s scan1")
        cmd = "sipvicious_svmap -s scan1 " + checkip
        cmd1 = "sipvicious_svreport export -f csv -o scan1.csv -t svmap -s scan1"
    # executing svmap scan and generating report with standard filename 'scan1.csv'
    os.system(cmd)
    os.system(cmd1)
    scan = csvparser("scan", "scan1.csv")
    # checking firmware
    firmware = checkfirmware(etalon, scan)
    # if there is no device in our firmware base we are just finishing the flow
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
    # parsing VoIPs for pairs Model - IP
    parsedvoips = parsevoips(scan)
    vulneredips = checkdefaultpasswords(parsedvoips)
    if vulneredips != []:
        printtable(vulneredips, "3", output)


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
