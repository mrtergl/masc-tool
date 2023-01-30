from genericpath import exists
import hashlib
from browser_history.browsers import Chrome
import requests
import json
import metadata
import base64
import time
import wmi
from pathlib import Path
import pandas as pd
import re
import psutil
from cfonts import render
from subprocess import check_output
import os
from colorama import Fore, Style
from malware_analysis.hexdump import HexDump
from malware_analysis import find_url
from datetime import datetime, timezone

home = str(Path.home())

try:
    os.mkdir(home + "/masc")
except OSError as error:
    pass

home = home + "/masc"

headers = {
    "Accept": "application/json",
    # YOUR OWN API KEY !!!
    "x-apikey": ""
}


def find(name):
    for root, dirs, files in os.walk("C:\\"):
        if name in files:
            return os.path.join(root, name)


def TxtToExcel(file):
    df = pd.read_csv(home + file + ".txt", sep=',')
    os.remove(home + file + ".txt")
    if exists(home + file + ".xlsx"):
        os.remove(home + file + ".xlsx")
    df.to_excel(home + file + '.xlsx', index=False)


def IP_STATS():
    open(home + "/Netstat.txt", "w").close()

    def Get_Ip():
        IP_List = set()
        with open(home + "/Netstat.txt", "r") as f_in:
            for line in map(str.strip, f_in):
                if not line or line == "State":
                    continue
                line = re.split(r"\s{2,}", line)
                if (len(line) == 5 and not "Foreign Address" in line[2] and not "0.0.0.0"
                                                                                in line[2] and not "127.0.0.1" in line[
                    2] and not "[::]" in line[2]):
                    if ":" in line[2]:
                        IP_List.add(line[2][:line[2].find(":")])
                    else:
                        IP_List.add(line[2])
                else:
                    continue
        return IP_List

    url = "https://www.virustotal.com/api/v3/ip_addresses/"

    out = check_output(["netstat", "-ano"])
    x = str(out, "utf-8")
    with open(home + "/Netstat.txt", 'a') as vt:
        vt.write(x)

    os.system("start " + home + "/Netstat.txt")
    #
    ans = input(str(Style.BRIGHT + Fore.GREEN +
                    "\nDo you want scan all the foreign IP Adresses in Virus Total ?[y/n]: " + Style.RESET_ALL))

    if ans == "y":
        with open(home + "/IP_RESULTS.txt", 'a') as vt:
            vt.write('IP,Harmless,Malicious,Suspicious,Undetected,Timeout\n\n')
        Ip_List_set = Get_Ip()
        Ip_List = list(Ip_List_set)
        Length = len(Ip_List)
        for ip in range(Length):
            url = "https://www.virustotal.com/api/v3/ip_addresses/"
            newurl = url + Ip_List[ip]
            response = requests.get(newurl, headers=headers)
            x = json.loads(response.content)
            if len(x["data"]) != 0:
                data = x["data"]["attributes"]["last_analysis_stats"]

                with open(home + "/IP_RESULTS.txt", 'a') as vt:
                    vt.write("{}".format(Ip_List[ip]))
                    for value in data.values():
                        vt.write(',{}'.format(value))
                    vt.write("\n")
                print("[{}/{}] DONE".format(ip + 1, Length))
            else:
                continue

        TxtToExcel("/IP_RESULTS")

        ans = input(str(Style.BRIGHT + Fore.GREEN +
                        "\nProcess has done. Would you like to open scanned IPs and results ? [y/n]: " + Style.RESET_ALL))

        if ans == "y":
            os.system("start " + home + "/IP_RESULTS.xlsx")
            menu()
        else:
            menu()

    elif ans == "n":
        menu()


def Browser_History():
    x = datetime.now(timezone.utc)
    print("\n")
    f = Chrome()
    outputs = f.fetch_history()

    for i in outputs.histories:
        if (x - i[0]).days > 0:
            outputs.histories.remove(i)
    outputs.save(home + "\history.csv")

    liste = []
    col_list = ["URL", "Timestamp"]
    df = pd.read_csv(home + '\history.csv', usecols=col_list)
    for i in range(len(df.index)):
        liste.append(df["URL"].iloc[i])

    i = 0

    for site in liste:
        url = "https://www.virustotal.com/api/v3/urls/"
        url_id = base64.urlsafe_b64encode(site.encode()).decode().strip("=")
        url = url + url_id
        response = requests.get(url, headers=headers)
        c = response.text
        x = json.loads(response.content)
        if "data" in x:
            data = x["data"]["attributes"]["last_analysis_stats"]["malicious"]
            if data <= 0:
                with open(home + '/URL_RESULT.txt', 'a') as vt:
                    vt.write(site) and vt.write(' -\tNOT MALICIOUS\n')
                    print("[{}/{}] DONE".format(i + 1, len(outputs.histories)))
            elif 1 <= data >= 3:
                with open(home + '/URL_RESULT.txt', 'a') as vt:
                    vt.write(site) and vt.write(' -\tMAYBE MALICIOUS\n')
                    print("[{}/{}] DONE".format(i + 1, len(outputs.histories)))
            elif data >= 4:
                with open(home + '/URL_RESULT.txt', 'a') as vt:
                    vt.write(site) and vt.write(' -\tMALICIOUS\n')
                    print("[{}/{}] DONE".format(i + 1, len(outputs.histories)))
            else:
                print("[{}/{}] URL NOT FOUND ON VIRUSTOTAL !".format(i +
                                                                     1, len(outputs.histories)))
        else:
            print("[{}/{}] URL NOT FOUND ON VIRUSTOTAL !".format(i +
                                                                 1, len(outputs.histories)))

        i = i + 1
        time.sleep(2)
    os.remove(home + '\history.csv')
    print("SCANNING COMPLETED")


def HASH_SCAN():
    print("\n")
    liste = []
    f = wmi.WMI()
    for process in f.Win32_Process():
        file_extension = Path(process.Name).suffix
        if file_extension == '.exe':
            liste.append(process.Name)

    with open(home + "/vt_Result_exe.txt", 'a') as vt:
        vt.write(
            'Name,Hash,Harmless,Type Unsupported,Suspicious,Confirmed Timeout,Confirmed Timeout,Failure,Malicious,Undetected\n\n')

    for i in range(len(liste)):
        path = find(liste[i])
        if type(path) == str:
            try:
                with open(path, "rb") as f:
                    bytes = f.read()
                    readable_hash = hashlib.md5(bytes).hexdigest()
                url = "https://www.virustotal.com/api/v3/search?query="
                url = url + readable_hash
                response = requests.get(url, headers=headers)
                x = json.loads(response.content)
                del x["links"]
                if len(x["data"]) != 0:
                    data = x["data"][0]["attributes"]["last_analysis_stats"]
                    with open(home + "/vt_Result_exe.txt", 'a') as vt:
                        vt.write("{},{}".format(liste[i], readable_hash))
                        for value in data.values():
                            vt.write(',{}'.format(value))
                        vt.write("\n")
                    print("[{}/{}] DONE".format(i + 1, len(liste)))
                else:
                    with open(home + "/vt_Result_exe.txt", 'a') as vt:
                        vt.write("{},Built-in-Service".format(liste[i]))
                        vt.write("\n")
                    print("[{}/{}] DONE".format(i, len(liste)))
            except OSError:
                with open(home + "/vt_Result_exe.txt", 'a') as vt:
                    vt.write("{},{},DOSYA YOLU OKUNAMADI".format(
                        liste[i], readable_hash))
        else:
            with open(home + "/vt_Result_exe.txt", 'a') as vt:
                vt.write("{},NOT FOUND".format(liste[i]))
                vt.write("\n")
            print("[{}/{}] DONE".format(i, len(liste)))

    TxtToExcel("/vt_Result_exe")

    print("SCANNING COMPLETED")


def win32_service():
    def getService():
        with open(home + "/win32_services.txt", 'w') as vt:
            vt.write('Name,Display Name,Process ID, Status\n\n')
        services = psutil.win_service_iter()
        with open(home + "/win32_services.txt", 'a', encoding="utf-8") as vt:
            for x in services:
                vt.write("{},{},{},{}\n".format(
                    x.name(), x.display_name(), x.pid(), x.status()))

    getService()

    TxtToExcel("/win32_services")

    ans = input(str(Style.BRIGHT + Fore.GREEN +
                    "\nService file created.Would you like to open the file to see all services? [y/n]: " + Style.RESET_ALL))

    if ans == "y":
        os.system("start " + home + "\win32_services.xlsx")
        menu()
    else:
        menu()


def Startups():
    print(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "\nLoading...\n" + Style.RESET_ALL)

    c = wmi.WMI()

    wql = "SELECT * FROM Win32_StartupCommand"

    with open(home + "/Startups.txt", 'a') as vt:
        vt.write("Name,Caption,Description,User,Location\n")
        for x in c.query(wql):
            vt.write("{},{},{},{},{}".format(
                x.Name, x.Caption, x.Description, x.User, x.Location))
            vt.write("\n")

    TxtToExcel("/Startups")

    print(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "DONE" + Style.RESET_ALL)
    ans = input(str(Style.BRIGHT + Fore.GREEN +
                    "\nStartup file created. Would you like to open the file ? [y/n]: " + Style.RESET_ALL))

    if ans == "y":
        os.system("start " + home + "\Startups.xlsx")
        menu()
    else:
        menu()


def UploadFile():
    def upload(file):
        print(Fore.LIGHTYELLOW_EX + "Searching the file..." + Style.RESET_ALL)
        url = "https://www.virustotal.com/api/v3/files"
        try:
            files = {"file": open(find(file), "rb")}
            print(Style.BRIGHT + Fore.LIGHTYELLOW_EX +
                  "\nFile Found !" + Style.RESET_ALL)
            response = requests.post(url, files=files, headers=headers)
            id = json.loads(response.content)["data"]["id"]
            print(Style.BRIGHT + Fore.LIGHTYELLOW_EX +
                  "\nFile Uploaded !\n" + Style.RESET_ALL)
            return id
        except TypeError:
            print(Style.BRIGHT + Fore.LIGHTRED_EX +
                  "File name is wrong or file is missing !" + Style.RESET_ALL)
            return menu()

    def get_upload_analysis(file):
        url = "https://www.virustotal.com/api/v3/analyses/" + upload(file)
        filename = home + "/" + file + "_analysis.txt"
        response = requests.get(url, headers=headers)
        x = json.loads(response.content)
        with open(filename, 'a') as vt:
            vt.write(
                'Name,Harmless,Type Unsupported,Suspicious,Confirmed Timeout,Timeout,Failure,Malicious,Undetected\n\n')

        print("Fetching the data.. Please Wait. This may take a couple of minutes.")

        while (x["data"]["attributes"]["status"] != "completed"):
            time.sleep(10)
            response = requests.get(url, headers=headers)
            x = json.loads(response.content)
            print("Loading...")
        if len(x["data"]) != 0:
            data = x["data"]["attributes"]["stats"]
            with open(filename, 'a') as vt:
                vt.write("{}".format(file))
                for value in data.values():
                    vt.write(',{}'.format(value))
                vt.write("\n")
            print(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "\nDONE !" + Style.RESET_ALL)
            return filename
        else:
            with open(filename, 'a') as vt:
                vt.write("{},Built-in-Service".format(file))
                vt.write("\n")
            print(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "\nDONE !" + Style.RESET_ALL)

    file = input(Style.BRIGHT + Fore.GREEN +
                 "\nPlease write the name of the file with its extension that you want to upload: " + Fore.LIGHTYELLOW_EX)
    print(Style.RESET_ALL)
    get_upload_analysis(str(file))
    filename = "/" + file + "_analysis"
    TxtToExcel(filename)

    ans = input(Style.BRIGHT + Fore.GREEN +
                "\nDo you want to open the file report ?[y/n]: " + Style.RESET_ALL)

    if ans == "y":
        os.system("start " + home + filename + ".xlsx")
        menu()
    else:
        menu()


def number_to_string(argument):
    match argument:
        case 0:
            exit()
        case 1:
            try:
                file = input(str(Style.BRIGHT + Fore.YELLOW +
                                 "Serach .exe file to analyse: " + Style.RESET_ALL))
                print(Style.NORMAL + Fore.YELLOW +
                      "\nLooking for file..." + Style.RESET_ALL)
                f = find(file)
                object = metadata.metadata()
                print(Style.NORMAL + Fore.YELLOW + "\nFile Information: ")
                print("==================\n" + Style.RESET_ALL)
                print(object.CheckFile(f, file))
            except Exception as e:
                print(str(e))

            while True:
                print("\n")
                print(Style.BRIGHT + Fore.YELLOW + '1' + Style.RESET_ALL +
                      ' -- Get HEX Format of the file' + Style.RESET_ALL)
                print(Style.BRIGHT + Fore.YELLOW + '2' +
                      Style.RESET_ALL + ' -- Get IP and URLs in File')
                print(Style.BRIGHT + Fore.YELLOW + '0' +
                      Style.RESET_ALL + ' -- Return Main Menu"\n')
                options = int(input(Style.BRIGHT + Fore.LIGHTGREEN_EX +
                                    'Enter Your Choice: ' + Style.RESET_ALL))
                match options:
                    case 0:
                        return False
                    case 1:
                        object = HexDump()
                        object.main(f, file)
                    case 2:
                        object = find_url.FindUrl()
                        object.main(f, file)
        case 2:
            print("\n")
            print(Style.BRIGHT + Fore.YELLOW + '1' + Style.RESET_ALL +
                  ' -- VirusTotal Browser History Control' + Style.RESET_ALL)
            print(Style.BRIGHT + Fore.YELLOW + '2' + Style.RESET_ALL +
                  ' -- Get all the Windows Services' + Style.RESET_ALL)
            print(Style.BRIGHT + Fore.YELLOW + '3' + Style.RESET_ALL +
                  ' -- Get Startup Files' + Style.RESET_ALL)
            print(Style.BRIGHT + Fore.YELLOW + '4' + Style.RESET_ALL +
                  ' -- Get Netstat Connection Table and Foreign IP addresses' + Style.RESET_ALL)
            print(Style.BRIGHT + Fore.YELLOW + '5' + Style.RESET_ALL +
                  ' -- VirusTotal File Upload and Analyse' + Style.RESET_ALL)
            print(Style.BRIGHT + Fore.YELLOW + '6' + Style.RESET_ALL +
                  ' -- Scan all the processes' + Style.RESET_ALL)
            print(Style.BRIGHT + Fore.YELLOW + '0' +
                  Style.RESET_ALL + ' -- Return Main Menu\n')
            option = int(input(Style.BRIGHT + Fore.LIGHTGREEN_EX +
                               'Enter Your Choice: ' + Style.RESET_ALL))
            System_analyse(option)


def menu():
    while True:
        output = render('SecTool', colors=[
            'green', 'white'], align='center', font='slick')
        print(output)
        print(Style.BRIGHT + Fore.YELLOW + '1' + Style.RESET_ALL +
              ' -- File Analyse' + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.YELLOW + '2' + Style.RESET_ALL +
              ' -- VirusTotal Browser History Control' + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.YELLOW + '3' + Style.RESET_ALL +
              ' -- Get all the Windows Services' + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.YELLOW + '4' + Style.RESET_ALL +
              ' -- Get Startup Files' + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.YELLOW + '5' + Style.RESET_ALL +
              ' -- Get Netstat Connection Table and Foreign IP addresses' + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.YELLOW + '6' + Style.RESET_ALL +
              ' -- VirusTotal File Upload and Analyse' + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.YELLOW + '6' + Style.RESET_ALL +
              ' -- Scan all the processes' + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.YELLOW + '0' + Style.RESET_ALL + ' -- Exit\n')
        option = int(input(Style.BRIGHT + Fore.LIGHTYELLOW_EX +
                           'Enter Your Choice: ' + Style.RESET_ALL))

        number_to_string(option)


def System_analyse(arg):
    match arg:
        case 1:
            return Browser_History()
        case 6:
            return HASH_SCAN()
        case 2:
            return win32_service()
        case 3:
            return Startups()
        case 4:
            return IP_STATS()
        case 5:
            return UploadFile()


def main_menu():
    while True:
        output = render('SecTool', colors=[
            'green', 'white'], align='center', font='slick')
        print(output)
        print(Style.BRIGHT + Fore.YELLOW + '1' + Style.RESET_ALL +
              ' -- File Analyse' + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.YELLOW + '2' + Style.RESET_ALL +
              ' -- System Analyse' + Style.RESET_ALL)
        print("\n")
        option = int(input(Style.BRIGHT + Fore.LIGHTGREEN_EX +
                           'Enter Your Choice: ' + Style.RESET_ALL + Style.BRIGHT + Fore.YELLOW))
        number_to_string(option)


main_menu()
