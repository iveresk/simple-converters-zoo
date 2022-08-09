import csv
import argparse
import os
import random
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys


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
    for i in range(0, len(firmware),2):
        firmwarespace = firmware[i].split(" ")
        for ii in range(0, len(firmwarespace)):
            for j in range(0, len(basecve), 2):
                basespace = basecve[j].split(";")
                if firmwarespace[ii] in basespace[1]:
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
            try:
                index2 = index2 + "1." + index1[2]
            except:
                pass
            index = index2.split(".")
            for i in range(0, len(index)):
                if index[0] == "1":
                    r = index[i].split(" ")
                    if len(r) > 1:
                        res = res + r[0]
                        int(res)
                        temp = int(res)
                        continue
                    r = index[i].split("'")
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
        for j in range(0, len(scan)):
            index = scan[j].split(" ")
            for k in range(1, len(index)):
                if index[k] == '':
                    break
                if index[k] in etalon[i] or etalon[i] in index[k]:
                    report.append(scan[j-1])
                    report.append(scan[j])
                    version = etalon[i].split(";")
                    report.append(version[1])
                    break
    return report


def csvparser(csvfile):
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
    file.close()
    for row in rows:
        for col in row:
            if col in '':
                continue
            if col in 'N/A':
                continue
            res.append(col)
    return res


def parsevoips(scans):
    res = []
    bytefree = []
    for i in range(0, len(scans)):
        try:
            bytefree.append(scans[i].split("b'")[1])
        except:
            bytefree.append(scans[i].split("b'")[0])
    for i in range(1, len(bytefree), 2):
        res.append(bytefree[i].split(" ")[0])
        res.append(bytefree[i-1].split(":")[0])
    return res


def getGSsession():
    # Session should be randomly generated where the 10th symbol is 'e'
    rand = ""
    for i in range(0, 21):
        if i == 10:
            rand = rand + "e"
            continue
        rand = rand + str(random.randint(0, 9))
    cookies = {'session-role': 'user', 'session-identity': rand, 'device': 'c0%3A74%3Aad%3A12%3Ac9%3Ac6', 'TRACKID': 'b2d11a71721a8b7d4b4872df12d278d2'}
    return cookies


def prepareGSheader(targetip):
    url = "http://" + targetip
    headers = {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate', 'Accept-Language': 'en-US,en;q=0.5', 'Cache-Control': 'max-age=0, no-cache', 'Connection': 'keep-alive', 'Content-Length': '40', 'Content-Type': 'application/x-www-form-urlencoded', 'Host': targetip, 'Origin': 'http://'+ targetip, 'Pragma': 'no-cache', 'Referer': 'http://'+ targetip, 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'}
    cookies = getGSsession()
    return url, headers, cookies


def checkdefaultpasswords(parsedvoips, path):
    vulns = []
    fillsleep = 3
    buttonsleep = 5
    requestsleep = 10
    # default passwords for the Grandstreams
    defaultpasses = {'Grandstream': ['user', '123', 'admin', 'admin']}
    for i in range(0, len(parsedvoips), 2):
        # requesting main params for the request
        url, headers, cookies = prepareGSheader(parsedvoips[i + 1])
        if "Grandstream" in parsedvoips[i]:
            for j in range(0, len(defaultpasses['Grandstream']), 2):
                try:
                    web = webdriver.Chrome(executable_path=path)
                    web.get(url)
                    time.sleep(requestsleep)
                    inputs = web.find_elements(By.TAG_NAME, "input")
                    if len(inputs) == 4 or len(inputs) == 5:
                        inputs[1].clear()
                        inputs[1].send_keys(defaultpasses['Grandstream'][j])
                        time.sleep(fillsleep)
                        inputs[2].clear()
                        inputs[2].send_keys(defaultpasses['Grandstream'][j+1])
                        time.sleep(fillsleep)
                        inputs[3].send_keys(Keys.ENTER)
                        time.sleep(buttonsleep)
                    elif len(inputs) == 3:
                        inputs[0].clear()
                        inputs[0].send_keys(defaultpasses['Grandstream'][j + 1])
                        time.sleep(fillsleep)
                        inputs[1].send_keys(Keys.ENTER)
                        time.sleep(buttonsleep)
                    elif len(inputs) == 2:
                        inputs[0].clear()
                        inputs[0].send_keys(defaultpasses['Grandstream'][j])
                        time.sleep(fillsleep)
                        inputs[1].clear()
                        inputs[1].send_keys(defaultpasses['Grandstream'][j + 1])
                        time.sleep(fillsleep)
                        button = web.find_element(By.TAG_NAME, "input")
                        button.send_keys(Keys.ENTER)
                        time.sleep(buttonsleep)
                    texts = web.find_elements(By.TAG_NAME, "b")
                    if texts is None or texts == []:
                        links = web.find_elements(By.TAG_NAME, "a")
                        if links is None or links == []:
                            web.close()
                            web.quit()
                            continue
                    for text in texts:
                        if "MAC" in text.text or "SETTINGS" in text.text:
                            vulns.append(parsedvoips[i])
                            vulns.append(parsedvoips[i + 1])
                            vulns.append(defaultpasses['Grandstream'][j])
                            vulns.append(defaultpasses['Grandstream'][j + 1])
                            break
                    for link in links:
                        if "logout" in link.text or "Logout" in link.text  or "Логаут" in link.text:
                            vulns.append(parsedvoips[i])
                            vulns.append(parsedvoips[i + 1])
                            vulns.append(defaultpasses['Grandstream'][j])
                            vulns.append(defaultpasses['Grandstream'][j + 1])
                            break
                    web.close()
                    web.quit()
                except:
                    web.close()
                    web.quit()
                    continue
    return vulns

def main(gcsvfile, checkip, system, output, path):
    # parsing firmwares
    etalon = csvparser(gcsvfile)
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
    scan = csvparser("scan1.csv")
    # checking firmware
    firmware = checkfirmware(etalon, scan)
    # if there is no device in our firmware base we are just finishing the flow
    if firmware == []:
        return
    printtable(firmware, "1", output)
    # CSV CVE Base
    csvbase = csvparser("gscvebase.csv")
    # transform versions
    firmware_transformed = transformversions(firmware)
    base_transformed = transformversions(csvbase)
    # Calculate versions
    report = calculateversions(firmware_transformed, base_transformed)
    if report != []:
        printtable(report, "2", output)
    # parsing VoIPs for pairs Model - IP
    parsedvoips = parsevoips(scan)
    vulneredips = checkdefaultpasswords(parsedvoips, path)
    if vulneredips != []:
        printtable(vulneredips, "3", output)


if __name__ == '__main__':
    # default parameters
    system = "kali"
    regime = "console"
    path = "/home/kali/chromedriver"
    # parsing input
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--versions', type=str, required=True)
    parser.add_argument('-i', '--ip', type=str, required=True)
    parser.add_argument('-s', '--system', type=str, required=False)
    parser.add_argument('-o', '--output', type=str, required=False)
    parser.add_argument('-p', '--path', type=str, required=False)
    args = parser.parse_args()
    # if system -s key exists we are overwriting the default value
    if args.system is not None:
        system = args.system
    # setting path to a chromedriver
    if args.path is not None:
        path = args.path
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
            main(args.versions, ip[0], system, regime, path)
    else:
        main(args.versions, args.ip, system, regime, path)
