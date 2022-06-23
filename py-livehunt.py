import os
import json
import re
import requests
import datetime as dt
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path)

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL")
VTAPI = os.environ.get("VTAPI")
RULENAME = os.environ.get("RULE_NAME")
client = WebClient(token=SLACK_BOT_TOKEN)

headers = {
   "x-apikey": VTAPI
}

def fetch_notification():
    limit = 10
    report = ""
    count = 0

    # prepare date filter
    today = dt.date.today()
    yesterday = today - dt.timedelta(days=1)
    day_after_before = today - dt.timedelta(days=2)

    # UTC
    # start_dt = day_after_before.strftime("%Y-%m-%d") + "T15:00:00+"
    # end_dt = yesterday.strftime("%Y-%m-%d") + "T15:00:00-"

    # JST
    start_dt = yesterday.strftime("%Y-%m-%d") + "T00:00:00+"
    end_dt = today.strftime("%Y-%m-%d") + "T00:00:00-"

    if not RULENAME:
        filter = "date:" + start_dt + " date:" + end_dt
        # demo_filter = "date:2021-09-11T17:33:00+ date:2021-09-16T17:35:00-"
    else:
        filter = "date:" + start_dt + " date:" + end_dt + " tag:" + RULENAME
        # demo_filter = "date:2021-09-11T17:33:00+ date:2021-09-16T17:35:00- tag:" + RULENAME

    # prepare report timestamp
    # UTC
    # report_from = day_after_before.strftime("%Y-%m-%d") + " 15:00:00 UTC"
    # report_to = yesterday.strftime("%Y-%m-%d") + " 15:00:00 UTC"

    # JST
    report_from = yesterday.strftime("%Y-%m-%d") + " 09:00:00 JST"
    report_to = today.strftime("%Y-%m-%d") + " 09:00:00 JST"

    # prepare request for VT
    vturl = "https://www.virustotal.com/api/v3/intelligence/hunting_notification_files"

    params = {
        "limit": limit, 
        "filter": filter
        # "filter": demo_filter
    }

    # get notification
    response = requests.get(vturl, params=params, headers=headers)
    result = json.loads(response.text)

    # metadata for report
    report += f"""\
VT Notifier got following alerts from livehunt during {report_from} - {report_to}.
This notification shows only {limit} results.
If you need to show more results, please modify parameter or visit VT site.
"""

    if not result["data"]:
        report += "====================\n"
        report += "No results.\n"
    else: 
        for data in result["data"]:
            utc_date = data["context_attributes"]["notification_date"]
            date = dt.datetime.utcfromtimestamp(utc_date).strftime('%Y/%m/%d %H:%M:%S') + " (UTC)"
            file_id = data["id"]
            file_link = "https://www.virustotal.com/gui/file/" + file_id + "/detection"

            # check if meaningful_name exists
            if data.get("attributes"):
                attributes = data["attributes"]
                file_name = attributes.get("meaningful_name", "No meaningful names")
                file_name = attributes.get("meaningful_name", "No meaningful names")
            # if data["attributes"] doesn't exist at notification timing, the file may be deleted
            else:
                file_name = "File Not Found (maybe deleted)"

            notification_snippet_raw = data["context_attributes"]["notification_snippet"]
            # reformatting message in order to improve readability on slack
            notification_snippet_liner = re.sub("^.*  ", "", notification_snippet_raw, flags=re.MULTILINE).replace("\n","")
            notification_snippet_trim = re.sub("\*end_highlight\*\*begin_highlight\*", "", notification_snippet_liner)
            notification_snippet = re.sub("\*(begin|end)_highlight\*", "\u200b`", notification_snippet_trim)

            rule_name = data["context_attributes"]["rule_name"]

            item = f"""\
====================
Alert ID: {count} 
Notified At: {date}
File Name: {file_name}
File Link: {file_link}
Snippet:
{notification_snippet}
Rule Name: {rule_name}
"""
            report += item
            count += 1
    
    report += "====================\n"
    report += "*############ REMIND ############*\n"
    report += "*# Check the credential list for duplicates #*\n"
    report += "*################################*\n"
    report += "Have a good day!"
    print(report)
    return report

try:
    report = fetch_notification()
    response = client.chat_postMessage(channel=SLACK_CHANNEL, text=report, parse="none")
    # response = client.chat_postMessage(channel=SLACK_CHANNEL, text=report)
    # response = client.files_upload(channels=SLACK_CHANNEL, content=report, title="VT_Notifier")
except SlackApiError as e:
    # You will get a SlackApiError if "ok" is False
    assert e.response["ok"] is False
    assert e.response["error"]  # str like 'invalid_auth', 'channel_not_found'
    print(f"Got an error: {e.response['error']}")

