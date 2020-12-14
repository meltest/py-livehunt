# Overview
py-livehunt collects livehunt notification from VirusTotal, and send it to slack.

# Requirements

* python3 ( >= 3.6)

* python-dotenv [https://pypi.org/project/python-dotenv/](https://pypi.org/project/python-dotenv/)

* python-slack-sdk [https://github.com/slackapi/python-slack-sdk](https://github.com/slackapi/python-slack-sdk)

# Usage
```
Usage: python3 py-livehunt.py

# Install

```
git clone
cd py-livehunt
vi .env
 - enter your virus total API key to VTAPI
 - enter your slack bot token to SLACK_BOT_TOKEN
 - enter your slack channel id to SLACK_CHANNEL
python3 py-livehunt.py
```
