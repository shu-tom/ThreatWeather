#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# LICENSE
# the GNU General Public License version 2
#

import os
import re
import sys
import json
import datetime
import argparse
import linecache
import urllib.request

try:
    from bs4 import BeautifulSoup
    has_bs = True
except ImportError:
    has_bs = False

try:
    from twitter import *
    has_twitter = True
except ImportError:
    has_twitter = False

parser = argparse.ArgumentParser(description="Cyber threat level checker.")
parser.add_argument("-f", "--force", action="store_true", default=False,
                    help="All threaded level check.")
parser.add_argument("-s", "--sans", action="store_true", default=False,
                    help="Check SANS Infocon.")
parser.add_argument("-x", "--xforce", action="store_true", default=False,
                    help="Check IBM X-Force Alertcon.")
parser.add_argument("-t", "--threatcon", action="store_true", default=False,
                    help="Check Symantec Threatcon.")
parser.add_argument("-av", "--avg", action="store_true", default=False,
                    help="Check AVG internet risk level.")
parser.add_argument("-ah", "--ahnlab", action="store_true", default=False,
                    help="Check Ahnlab Security Risk Level.")
parser.add_argument("-m", "--msisac", action="store_true", default=False,
                    help="Check MS-ISAC Alert Level.")
parser.add_argument("-w", "--wizardry", action="store_true", default=False,
                    help="Check SecurityWizardry.com overall alert.")
parser.add_argument("-l", "--logs", dest="logs", action="store", type=str, metavar="DIRECTORY",
                    help="Set the log file directory.")
parser.add_argument("--tweet", action="store_true", default=False,
                    help="Post to twitter.")
args = parser.parse_args()

USER_AGENT = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:35.0) Gecko/20100101 Firefox/70.0"

# Twitter post message
POST_MESSAGE = "{0}: Alert level changed from {1} to {2}. {3} #ThreatWeather"

# Twitter API key
TW_CONSUMER_KEY    = ""
TW_CONSUMER_SECRET = ""
TW_TOKEN           = ""
TW_TOKEN_SECRET    = ""

# Folder path
FPATH = os.path.dirname(os.path.abspath(__file__))

# Console colors
BLACK  = '\033[40m'
RED    = '\033[41m'
GREEN  = '\033[42m'
YELLOW = '\033[43m'
ORANGE = '\033[0;103m'
BLUE   = '\033[44m'
END    = '\033[0m'

INFOCON_COLOR = {
    "green": GREEN,
    "yellow": YELLOW,
    "orange": ORANGE,
    "red": RED
}

ALERTCON_COLOR = {
    "level1": GREEN,
    "level2": BLUE,
    "level3": YELLOW,
    "level4": RED
}

THREATCON_COLOR = {
    "level1": GREEN,
    "level2": YELLOW,
    "level3": ORANGE,
    "level4": RED
}

AVG_COLOR = {
    "GENERAL RISK": GREEN,
    "ELEVATED RISK": YELLOW,
    "HIGH RISK": ORANGE,
    "EXTREME RISK": RED
}

AHNLAB_COLOR = {
    "Low": GREEN,
    "Medium": BLUE,
    "High": ORANGE,
    "Critical": RED
}

MSISAC_COLOR = {
    "Low": GREEN,
    "Guarded": BLUE,
    "Elevated": YELLOW,
    "High": ORANGE,
    "Severe": RED
}

SW_COLOR = {
    "GUARDED": BLUE,
    "INCREASED": YELLOW,
    "HIGH": ORANGE,
    "CRITICAL": RED
}

STR_INFO = {
    "sans":      [INFOCON_COLOR, "https://isc.sans.edu/api/infocon?json",
                  "SANS Infocon", "https://isc.sans.edu/infocon.html"],
    "xforce":    [ALERTCON_COLOR, "https://exchange.xforce.ibmcloud.com/api/alertcon",
                  "IBM X-Force Alertcon", "https://exchange.xforce.ibmcloud.com/"],
    "threatcon": [THREATCON_COLOR, "https://www.symantec.com/security_response/threatcon/",
                  "Symantec Threatcon", "https://www.symantec.com/security_response/threatcon/"],
    "avg":       [AVG_COLOR, "https://www.avg.com/en-us/about-viruses",
                  "AVG internet risk level", "https://www.avg.com/en-us/about-viruses"],
    "ahnlab":    [AHNLAB_COLOR, "https://global.ahnlab.com/site/securitycenter/securitycenterMain.do",
                  "Ahnlab Security Risk Level", "https://global.ahnlab.com/site/securitycenter/securitycenterMain.do"],
    "msisac":    [MSISAC_COLOR, "https://www.cisecurity.org/cybersecurity-threats/",
                  "MS-ISAC Alert Level", "https://www.cisecurity.org/cybersecurity-threats/"],
    "wizardry":  [SW_COLOR, "https://www.securitywizardry.com/the-radar-page/overall-alerts",
                  "SecurityWizardry.com overall alert", "https://www.securitywizardry.com/the-radar-page/overall-alerts"]
}


def post_tweet(info, sig, status):
    if args.logs:
        log_dir = os.path.join(FPATH, args.logs)
        filename = os.path.join(log_dir, info + ".log")

        last_status = ""
        try:
            num_lines = sum(1 for line in open(filename, "r"))
            target_line = linecache.getline(filename, num_lines)
            last_status = target_line.split(",")[1].strip()
        except Exception as e:
            print("[!] FileError: ", e)

        if last_status and not str(last_status) in str(status):
            try:
                t = Twitter(auth=OAuth(TW_TOKEN, TW_TOKEN_SECRET, TW_CONSUMER_KEY, TW_CONSUMER_SECRET))
                msg = POST_MESSAGE.format(sig[2], last_status, status, sig[3])
                t.statuses.update(status=msg)
                print("[+] Tweet this message: {0}".format(msg))
            except Exception as e:
                print("[!] TweetError: ", e)
    else:
        print("[!] Please set option -l logs directory.")

def save_log(info, status):
    log_dir = os.path.join(FPATH, args.logs)

    if os.path.exists(log_dir) is False:
        os.mkdir(log_dir)
        print("[+] make log directory {0}.".format(log_dir))

    filename = os.path.join(log_dir, info + ".log")

    try:
        with open(filename, "a") as f:
            f.write("{0},{1}\n".format(datetime.datetime.now(), status))
    except Exception as e:
        print("[!] FileError: ", e)


def get_content(url):
    data = ""
    try:
        headers = {"User-Agent":  USER_AGENT}
        req = urllib.request.Request(url, None, headers)
        response = urllib.request.urlopen(req)
        data = response.read()
        response.close()
    except urllib.error.HTTPError as e:
        print("[!] HTTPError: ", e)

    return data


def get_json(url):
    json_data = ""
    data = get_content(url)
    try:
        json_data = json.loads(data.decode('utf-8'))
    except json.JSONDecodeError as e:
        print("[!] JSONDecodeError: ", e)

    return json_data


def get_html(url):
    data = get_content(url)
    soup = BeautifulSoup(data, 'lxml')

    return soup


def print_color(info, colors, status):
    print("[+] {0}:".format(info))
    line = "    | "
    for k, i in colors.items():
        if str(status).lower() in str(k).lower():
            line = line + "{0}{1:<13}{2} | ".format(i, k, END)
        else:
            line = line + "{0:<13} | ".format(k)

    print(line)


def main():
    if not has_bs:
        sys.exit("[!] Beautifulsoup4 must be installed for this script.")

    if not has_twitter and args.tweet:
        sys.exit("[!] twitter must be installed for this script.")

    print("[+] What's the threat weather like today?")

    if args.sans or args.force:
        sig = STR_INFO["sans"]
        data = get_json(sig[1])
        if data:
            status = data['status']
            print_color(sig[2], sig[0], status)

        if args.tweet:
            post_tweet("sans", sig, status)

        if args.logs:
            save_log("sans", status)

    if args.xforce or args.force:
        sig = STR_INFO["xforce"]
        data = get_json(sig[1])
        if data:
            status = data['alertcon']['level']
            print_color(sig[2], sig[0], status)

        if args.tweet:
            post_tweet("xforce", sig, status)

        if args.logs:
            save_log("xforce", status)

    if args.threatcon or args.force:
        sig = STR_INFO["threatcon"]
        data = get_html(sig[1])
        if data:
            html = data.find_all("img", class_="imgMrgnRgtLG")
            for a in html:
                status = a.get("src").split("/")[5].replace("threatcon-", "").replace(".png", "")
            print_color(sig[2], sig[0], status)

        if args.tweet:
            post_tweet("threatcon", sig, status)

        if args.logs:
            save_log("threatcon", status)

    if args.avg or args.force:
        sig = STR_INFO["avg"]
        data = get_html(sig[1])
        if data:
            html = data.find_all("img", alt=re.compile("Threatometer"))
            for a in html:
                index = a.get("src").split("/")[5].replace("risklevel_avg9_", "").replace("_en.png", "")
            status = list(AVG_COLOR.items())[int(index) - 1][0]
            print_color(sig[2], sig[0], status)

        if args.tweet:
            post_tweet("avg", sig, status)

        if args.logs:
            save_log("avg", status)

    if args.ahnlab or args.force:
        sig = STR_INFO["ahnlab"]
        data = get_html(sig[1])
        if data:
            html = data.find_all("p", class_="blind")
            for a in html:
                status = a.get_text().split(":")[1]
            print_color(sig[2], sig[0], status)

        if args.tweet:
            post_tweet("ahnlab", sig, status)

        if args.logs:
            save_log("ahnlab", status)

    if args.msisac or args.force:
        sig = STR_INFO["msisac"]
        data = get_html(sig[1])
        if data:
            html = data.find_all("div", class_="alert-level")
            for div in html:
                span = div.find_all("span")
                for a in span:
                    status = a.get_text()
            print_color(sig[2], sig[0], status)

        if args.tweet:
            post_tweet("msisac", sig, status)

        if args.logs:
            save_log("msisac", status)

    if args.wizardry or args.force:
        sig = STR_INFO["wizardry"]
        data = get_html(sig[1])
        if data:
            html = data.find_all("h4")
            for a in html:
                status = a.get_text()
                break
            print_color(sig[2], sig[0], status)

        if args.tweet:
            post_tweet("wizardry", sig, status)

        if args.logs:
            save_log("wizardry", status)

    print("[+] Done.")

if __name__ == "__main__":
    main()
