# Correlation Rules Runner

## Description

**Correlation Rules Runner** is a utility script that can run all or selected/filtered Splunk Enterprise Security correlation rules to see if they return hits.
It will save run results into a KV Store collection which can then be optionally scheduled in Enterprise Security using the same command.

## Requirements

- Python 3.x
- Python `pip` or another way to install dependencies
- Splunk Enterprise Security

The script uses the [Splunk Python SDK](https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/gettingstartedpython/installsdkpython/) (`splunk-sdk`) as well as the [Blessings](https://github.com/erikrose/blessings) (`blessings`) library.
Both can be installed by using: 
```commandline
pip install -r requirements.txt
```

Have a look at the link provided above for additional configuration details that might be required for the Splunk Python SDK.

## Syntax

```commandline
usage: cr_runner.py [options]...

Runs all or selected ES Correlation Searches and report which ones have hits. Saves results in a KV Store lookup named "detection_status_collection".

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        Splunk Server (Search Head) to connect to via REST (default: 127.0.0.1)
  -p PORT, --port PORT  Splunk Server management port (default: 8089)
  -u USER, --user USER  Splunk Server user to use for the connection (default: admin)
  -pw PASSWORD, --password PASSWORD
                        Splunk user password to use for the connection. If a user is supplied but no password is, it will be asked from the command line
  -f, --force           Force execution of correlation searches, even if previous results exist
  -t TOKEN, --token TOKEN
                        Splunk bearer token to use for the connection
  -te MITRE_TECHNIQUE, --mitre-technique MITRE_TECHNIQUE
                        One or more MITRE ATT&CK technique(s) to use in filtering correlation searches to execute. Separate multiple values with commas
  -l, --list            Do not execute correlation searches, simply list previous results (if any)
  -sc, --schedule       Do not execute correlation searches, simply schedule previous results (if any)
  -ed, --enabled-detections-only
                        Only execute correlation searches that are enabled
  -dd, --disabled-detections-only
                        Only execute correlation searches that are disabled
  -r, --reset           Reset the results collection (forces to re-run all detections)
  -v, --verbose         Display verbose messages about the script execution.
  --version             show program's version number and exit
```

## Examples

Connect to the Splunk server on localhost, using the admin user, asking for a password (prompt) and run all correlations:

`cr_runner.py`

Connect to Splunk server named `mysplunkserver.local` using the default user ("admin") and password (user will be prompted) and run all correlation rules:

`cr_runner.py -s splunk-sh.localdomain`

Connect to a Splunk server named `mysplunkserver.local` using an authentication token and run all correlation rules:

`cr_runner.py -s mysplunkserver.local -t eyJraWQiOiJzcGx...xTqHKsVC9Ir3mf70w0BjrzKCi49sw`

Connect to a named Splunk server and list previous run results:

`cr_runner.py -s mysplunkserver.local -l`

Reset the previous run(s) results in the KV store:

`cr_runner.py -s mysplunkserver.local -r`

Connect to a named Splunk server and run all currently disabled detections only:

`cr_runner.py -s mysplunkserver.local -dd`

Connect to a named Splunk server and run all detections matching MITRE techniques T1003.001 T1059.003 and T1038 only.  Run those detections even if previous results already exists, overwriting any:

`cr_runner.py -s mysplunkserver.local -te T1003.001,T1059.003,T1038 -f`

Here's an example run:

![example_run](https://user-images.githubusercontent.com/58239192/231543311-0792e201-9c24-4876-b2bb-aadc29beea0c.gif)

## Lookup

The results are stored in a KV store collection named `detection_status_collection` with a corresponding transform named `detection_status_collection_lookup`. 
Both get created in the `system` app context and are shared globally.

![image](https://user-images.githubusercontent.com/58239192/232083793-38503177-5e2d-4148-ad93-de568939e6d9.png)

## Notes & Feedback

If you have feedback on this utility script for Splunk ES (improvement ideas, issues, questions), feel free to contact me via email or open an issue on this project on GitHub.
