import os
import json
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

    start_dt = day_after_before.strftime("%Y-%m-%d") + "T15:00:00+"
    end_dt = yesterday.strftime("%Y-%m-%d") + "T15:00:00-"
    filter = "date:" + start_dt + " and date:" + end_dt
    # demo_filter = "date:2020-11-20T17:33:00+ and date:2020-11-20T17:35:00-"

    # prepare report timesamp
    report_from = day_after_before.strftime("%Y-%m-%d") + " 15:00:00 UTC"
    report_to = yesterday.strftime("%Y-%m-%d") + " 15:00:00 UTC"

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
VT notifier got following alerts from livehunt during {report_from} - {report_to}.
This notification shows only {limit} results.
If you need to show more results, please modify parameter or vist VT site.
"""

    if not result["data"]:
        report += "====================\n"
        report += "No results.\n"
    else: 
        for data in result["data"]:
            utc_date = data["context_attributes"]["notification_date"]
            date = dt.datetime.utcfromtimestamp(utc_date).strftime('%Y/%m/%d %H:%M:%S')
            file_id = data["id"]
            file_link = "https://www.virustotal.com/gui/file/" + file_id + "/detection"
            rule_name = data["context_attributes"]["rule_name"]

            item = f"""\
====================
alert id: {count} 
notifed at: {date}
file link: {file_link}
rule name: {rule_name}
"""
            report += item
            count += 1
    
    report += "====================\n"
    report += "Have a good day!"
    # print(report)
    return report

try:
    report = fetch_notification()
    # response = client.chat_postMessage(channel=SLACK_CHANNEL, text=report)
    response = client.files_upload(channels=SLACK_CHANNEL, content=report, title="VT_Notifier")
except SlackApiError as e:
    # You will get a SlackApiError if "ok" is False
    assert e.response["ok"] is False
    assert e.response["error"]  # str like 'invalid_auth', 'channel_not_found'
    print(f"Got an error: {e.response['error']}")

