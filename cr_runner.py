#!/usr/bin/env python3
#
# cr_runner.py
#
# C. Cloutier -  2022-11-25
# Run all or selected Security Detection searches in Splunk ES and save/report positive hits.
# Detections are run using their default earliest/latest configurations.
# Results are saved in the "detection_status_collection" KV Store lookup.
#
import argparse
import getpass
import json
import re
import signal
import sys
import time
from time import sleep

import splunklib.client as client
import splunklib.results as results
from blessings import Terminal
from splunklib.binding import HTTPError

VERSION = '1.0.0'


###
# Parse and validate command arguments.
###
def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        usage="%(prog)s [options]...",
        description="Runs all or selected ES Correlation Searches and report which ones have hits.  Saves results in a "
                    "KV Store lookup named \"detection_status_collection\"."
    )
    parser.add_argument(
        "-s", "--server", action="store",
        help="Splunk Server (Search Head) to connect to via REST (default: 127.0.0.1)",
        default='127.0.0.1'
    )
    parser.add_argument(
        "-p", "--port", action="store",
        help="Splunk Server management port (default: 8089)",
        default=8089
    )
    parser.add_argument(
        "-u", "--user", action="store",
        help="Splunk Server user to use for the connection (default: admin)",
        default='admin'
    )
    parser.add_argument(
        "-pw", "--password", action="store",
        help="Splunk user password to use for the connection. "
             "If a user is supplied but no password is, it will be asked from the command line"
    )
    parser.add_argument(
        "-f", "--force", action="store_true",
        help="Force execution of correlation searches, even if previous results exist",
        default=False
    )
    parser.add_argument(
        "-t", "--token", action="store",
        help="Splunk bearer token to use for the connection"
    )
    parser.add_argument(
        "-n", "--name", action="store",
        help="Only execute the correlation search matching this name. Takes precedence over any other filter."
    )
    parser.add_argument(
        "-cf", "--custom-filter", action="store",
        help="Used with -l or -sc, to apply a custom filter to the collection of results to list/schedule. See syntax and details here: https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTkvstore#Queries."
    )
    parser.add_argument(
        "-nh", "--include-no-hits", action="store_true",
        help="When used with -l or -sc to list/schedule detections, return all matching results (as opposed to only those with 'hits').",
        default=False
    )
    parser.add_argument(
        "-te", "--mitre-technique", action="store",
        help="One or more MITRE ATT&CK technique(s) to use in filtering correlation searches to execute. "
             "Separate multiple values with commas"
    )
    parser.add_argument(
        "-l", "--list", action="store_true",
        help="Do not execute correlation searches, simply list previous results (if any)"
    )
    parser.add_argument(
        "-sc", "--schedule", action="store_true",
        help="Do not execute correlation searches, simply schedule previous results (if any)"
    )
    parser.add_argument(
        "-ed", "--enabled-detections-only", action="store_true",
        help="Only execute correlation searches that are enabled"
    )
    parser.add_argument(
        "-dd", "--disabled-detections-only", action="store_true",
        help="Only execute correlation searches that are disabled"
    )
    parser.add_argument(
        "-r", "--reset", action="store_true",
        help="Reset the results collection (forces to re-run all detections)"
    )
    parser.add_argument(
        "-v", "--verbose", action='store_true',
        help="Display verbose messages about the script execution."
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{parser.prog} - v{VERSION}"
    )
    return parser


###
# Connect to a Splunk Search Head environment using a user/password or bearer token (which needs to be configured
# upfront).  Connections using a bearer token (when provided) takes precedence over using user/password credentials.
###
def connect(args) -> client.Service:
    if args.token is None:
        if args.password is None:
            password = getpass.getpass()
        else:
            password = args.password
        if args.verbose:
            log_verbose(f"Connecting to {args.server} on tcp/{args.port}, user: {args.user}")
        return client.connect(host=args.server, port=args.port, username=args.user, password=password, retries=3)
    else:
        if args.verbose:
            log_verbose(f"Connecting to {args.server} on tcp/{args.port}, bearer token: [{args.token}]")
        return client.connect(host=args.server, port=args.port, splunkToken=args.token, retries=3)


def validate_techniques(args_techniques) -> None:
    techniques = args_techniques.replace(" ", "")
    techniques_list = techniques.split(",")
    for technique in techniques_list:
        if not re.search("[Tt]\\d{4}(\\.\\d{3}|)", technique):
            log_error(
                f"Invalid mitre-technique argument value: {args_techniques}. Should be in the form --mitre-technique Txxxx or --mitre-technique Txxxx,Txxxx.xxx, etc.")
            sys.exit(2)


###
# Get a list of ES correlation rules from the Splunk environment.
# Of course, expects that Splunk Enterprise Security is installed.
###
def get_es_detections(args, service):
    # Check for specific filter and prepare an appropriate SPL filter accordingly.
    es_filter = ""
    if args.name is not None:
        es_filter = f"| search csearch_name = \"{args.name}\""
    if args.enabled_detections_only:
        es_filter += "| search disabled = 0"
    if args.disabled_detections_only:
        es_filter += "| search disabled = 1"
    if args.mitre_technique is not None:
        if "," in args.mitre_technique:
            techniques = args.mitre_technique.upper().replace(" ", "")
            es_filter += f"| search mitre_attack_technique IN ({techniques})"
        else:
            es_filter += f"| search mitre_attack_technique = {args.mitre_technique}"

    detection_search: str = """
  | rest splunk_server=local count=0 /services/saved/searches 
  | where isnotnull('action.correlationsearch.enabled') 
  | rename title as csearch_name, dispatch.earliest_time as earliest_time, dispatch.latest_time as latest_time, 
           action.notable.param.security_domain as security_domain, action.correlationsearch.annotations as annotations
  | spath output=mitre_attack_technique input=annotations path="mitre_attack{}"
  | table csearch_name, disabled, security_domain, mitre_attack_technique, earliest_time, latest_time, search
  | eval mitre_attack_technique = if(isnull(mitre_attack_technique), "", mitre_attack_technique)
  """
    detection_search += f"{es_filter}"

    validate_search(args, service, detection_search)

    if args.verbose:
        log_verbose(f"Running SPL: {detection_search}")

    kwargs_search = {"exec_mode": "blocking"}
    job = service.jobs.create(detection_search, **kwargs_search)

    result_stream = job.results(output_mode='json', count=0)
    reader = results.JSONResultsReader(result_stream)
    total = int(job["resultCount"])

    job.cancel()
    return total, reader


###
# Get the Detection status KV Store collection "detection_status_collection".
# Will create the collection and required knowledge objects if they do not exist.
###
def get_detection_status_collection(args, service):
    collection_name = "detection_status_collection"
    transform_name = "detection_status_collection_lookup"

    # Check if the relevant KVStore exists, if not create it along with the relevant transforms (collections.conf)
    if collection_name not in service.kvstore:
        if args.verbose:
            log_verbose(f"Creating KV Store collection {collection_name}.")
            log_verbose(f"Creating lookup transforms configuration {transform_name}.")
        service.kvstore.create(collection_name)
        transforms = service.confs['transforms']
        transforms.create(name=transform_name,
                          **{'external_type': 'kvstore', 'collection': collection_name,
                             'fields_list': '_key, name, results, disabled, updated, earliest, latest, techniques, search',
                             'owner': 'nobody'})

    return service.kvstore[collection_name]


###
# Check if a particular entry exists in the KV Store collection.
###
def exists_in_collection(collection, query) -> bool:
    if len(collection.data.query(query=query)) > 0:
        return True
    else:
        return False


###
# Remove entry if it exists in the KV Store collection.
###
def remove_from_collection(collection, query) -> None:
    entries = collection.data.query(query=query)
    if len(entries) > 0:
        collection.data.delete(json.dumps({"_key": entries[0]['_key']}))


###
# Save the results of running an ES CR search into the KV Store collection.
# Note: Failed searches will have a value of "-1" under results.
###
def add_to_collection(collection, detection, result_count) -> None:
    collection.data.insert(json.dumps(
        {"name": detection['csearch_name'],
         "results": str(int(result_count)),
         "disabled": str(int(detection['disabled'])),
         "updated": str(int(time.time())),
         "earliest": normalize_time(detection['earliest_time']),
         "latest": normalize_time(detection['latest_time']),
         "techniques": detection['mitre_attack_technique'],
         "search": detection['search']
         }
        )
    )


def validate_search(args, service, search) -> bool:
    try:
        service.parse(search, parse_only=True)
        return True
    except HTTPError as e:
        if e.status == 409:
            if args.verbose:
                log_verbose("Query cannot be parsed for validity: {}".format(str(e)))
            return True
        else:
            log_error(f"Query '{search}' is invalid:\n\t{str(e)}")
            log_error("Skipping...")
            sleep(3)
            return False


###
# Runs a Splunk Search in Normal mode, using the current configuration of the correlation search
# (earliest, latest) for the time window.
###
def run_search(args, service, search, earliest, latest, t) -> int:
    search = normalize_search(search)

    if validate_search(args, service, search):
        kwargs_normalsearch = {"exec_mode": "normal", "earliest_time": earliest, "latest_time": latest}
        job = service.jobs.create(search, **kwargs_normalsearch)

        while True:
            while not job.is_ready():
                pass
            stats = {"isDone": job["isDone"],
                     "dispatchState": job["dispatchState"],
                     "doneProgress": float(job["doneProgress"]) * 100,
                     "scanCount": int(job["scanCount"]),
                     "eventCount": int(job["eventCount"]),
                     "resultCount": int(job["resultCount"])}

            status = ("\r%(doneProgress)03.1f%%   %(scanCount)d scanned   "
                      "%(eventCount)d matched   %(resultCount)d results   -   %(dispatchState)s") % stats

            # Display current search progress at the bottom of the terminal window.
            with t.location(0, t.height - 1):
                print(t.clear_eol(), end='')
                print(f"{t.normal}{status}", end='', flush=True)

            if stats["isDone"] == "1":
                break

        search_results = int(job["resultCount"])
        job.cancel()

        return search_results

    # Return -1 in case the Search failed to execute.
    # There might be an issue with it, and that allows the user to investigate those later.
    return -1


###
# Normalize searches meant for the UI so that they are properly formatted (ex:they start with "search" when applicable).
###
def normalize_search(search) -> str:
    if search.startswith("|"):
        return search

    if search.lower().startswith("search "):
        return search

    normalized = "search {}".format(search)
    return normalized


###
# Convert realtime Correlation Searches to normal searches for the purpose of testing if they return hits.
###
def normalize_time(time_indicator) -> str:
    return time_indicator.removeprefix("rt")


###
# Log errors in a standardized format.
###
def log_error(e) -> None:
    """
    It is always a good idea to log errors.
    This function just prints them, but should be improved!
    """
    t = Terminal()
    print(f"{t.bold_red}ERROR: {e}{t.normal}")


###
# Log verbose messages in a standardized format.
###
def log_verbose(e) -> None:
    t = Terminal()
    print(f"{t.bold_green}\nINFO: {e}{t.normal}")


###
# Gracefully catch CTRL + C process interruption.
###
def sigint_handler():
    t = Terminal()
    print(f"{t.bold_red}\nCTRL + C was pressed.  Interrupting script execution.{t.normal}")
    sys.exit(2)


###
# Get a friendly description of the security detection filter.
###
def get_filter_description(args) -> str:
    if args.name is not None:
        return f"{args.name}"
    if args.custom_filter:
        return "custom filter"
    if args.enabled_detections_only:
        return "list of Enabled"
    if args.disabled_detections_only:
        return "list of Disabled"
    if args.mitre_technique:
        return "list of selected MITRE ATT&CK Techniques"
    return "All"


###
# List results that have already been gathered from the KV Store collection.
###
def list_results(collection, args, t):
    print(f"{t.bold}\nResults for {get_filter_description(args)} detection(s) in collection:{t.normal}")
    query = json.dumps(get_collection_filter(args))
    query_results = collection.data.query(query=query)
    if len(query_results) > 0:
        print(
            "{t.bold_yellow_underline}{:<14}{t.normal}{:<101}{t.bold}{t.yellow}{t.underline}{:<5}{t.normal}".format(
                "Detection Name", "", "Hits", t=t))
        for result in query_results:
            print(f"{t.yellow}{result['name']:<115}{result['results']:<5}{t.normal}")
    else:
        print(f"{t.yellow}None{t.normal}")


###
# Build KVStore query for requested MITRE techniques.
###
def get_query_for_techniques(mitre_techniques) -> dict:
    if mitre_techniques is None:
        pass
    query = {"$or": []}
    for mitre_technique in mitre_techniques.replace(" ", "").split(","):
        query["$or"].append({"techniques": mitre_technique})

    return query


###
# Filter collection results based on command arguments.
###
def get_collection_filter(args) -> dict:
    filter = {"$and": []}

    if args.name:
        filter["$and"].append({"name": args.name})
    if args.custom_filter:
        filter["$and"].append(json.loads(args.custom_filter))
    if args.enabled_detections_only:
        filter["$and"].append({"disabled": {"$lte": "0"}})
    if args.disabled_detections_only:
        filter["$and"].append({"disabled": {"$gte": "1"}})
    if args.mitre_technique:
        filter["$and"].append(get_query_for_techniques(args.mitre_technique))

    if not args.include_no_hits:
        filter["$and"].append({"results": {"$gt": "0"}})  # Return only results that had hits.

    return filter


###
# Schedule all detections that were previously tested and shown to return at least one result.
###
def schedule_detections(args, service, collection, t):
    print(f"{t.bold}\nScheduling {get_filter_description(args)} detection(s) in collection:{t.normal}")
    query = json.dumps(get_collection_filter(args))
    query_results = collection.data.query(query=query)
    results_count = len(query_results)
    if results_count > 0:
        print(f"{t.bold}{results_count} detection(s) in collection to schedule...{t.normal}")
        saved_searches = service.saved_searches
        for result in query_results:
            schedule_detection(saved_searches, result, t)
    else:
        print(f"{t.yellow}No detection with results in collection. Did you execute detections first?{t.normal}")


###
# Schedule a Correlation Rule in ES.
###
def schedule_detection(saved_searches, result, t):
    search_name = result['name']
    print(f"{t.bold}Scheduling Correlation Rule {t.blue}{search_name}{t.normal}{t.bold}... {t.normal}", end='',
          flush=True)
    if search_name in saved_searches:
        search = saved_searches[search_name]
        if search["disabled"] == '1' or search["is_scheduled"] != '1':
            kwargs = {
                "is_scheduled": True,
                "disabled": False
            }
            search.update(**kwargs).refresh()
            print(f"{t.bold_green}done.{t.normal} Next run: {search['next_scheduled_time']}.")
        else:
            print(f"{t.bold_yellow}already scheduled.{t.normal}")
        sys.exit(0)


###
# Execute all detections and gather results
###
def execute_detections(args, service, collection, t):
    print(f"{t.bold}Getting {get_filter_description(args)} ES Security Detection(s)... {t.normal}", end='',
          flush=True)

    total, detections = get_es_detections(args, service)

    print(f"{t.bold_green}{total} detections found.{t.normal}")
    sleep(1)

    current = 1
    triggered_detections = []

    for detection in detections:
        if isinstance(detection, dict):
            print(t.clear())

            current_label = "[{}/{} - {}%]".format(current, total, round(current / total * 100, 2))
            search = detection['search']
            earliest = normalize_time(detection['earliest_time'])
            latest = normalize_time(detection['latest_time'])

            print(
                "========================================================================================================================")
            print(f"{t.yellow}{detection['csearch_name']:<100}{t.bold}{current_label:>20}{t.normal}")
            print(
                "========================================================================================================================")
            if search is not None:
                print(f"{t.green}{search}{t.normal}")
                print(f"{t.yellow}Earliest: {earliest} - Latest: {latest}{t.normal}")
            else:
                log_error("Search is empty.")

            # Only run a search if we don't already have results for it in the collection unless forced.
            if args.force or not exists_in_collection(collection, json.dumps({"name": detection['csearch_name']})):
                result_count = run_search(args, service, search.strip(), earliest, latest, t)
                if args.force:
                    remove_from_collection(collection, json.dumps({"name": detection['csearch_name']}))
                add_to_collection(collection, detection, result_count)
                if result_count > 0:
                    triggered_detections.append(detection['csearch_name'])
            current += 1

    print(t.clear())
    print(t.move(0, 0))

    print(f"{t.bold}{t.underline}Triggered Detections in current run:{t.normal}")
    if len(triggered_detections) > 0:
        for result in triggered_detections:
            print(f"{t.yellow}{result}{t.normal}")
    else:
        print(f"{t.yellow}None{t.normal}")

    print(f"{t.bold_underline}\nTriggered Detections in previous runs:{t.normal}")
    query = json.dumps({"results": {"$gt": "0"}})
    query_results = collection.data.query(query=query)
    if len(query_results) > 0:
        for result in query_results:
            detection_name = result['name']
            if detection_name not in triggered_detections:
                print(f"{t.yellow}{result['name']}{t.normal}")
    else:
        print(f"{t.yellow}None{t.normal}")


###
# Perform any other validation of arguments needed.
###
def additional_args_validation(args):
    if args.enabled_detections_only and args.disabled_detections_only:
        log_error("You cannot use both --enabled-detections-only and --disabled--detections-only at the same time.")
        sys.exit(1)
    if args.mitre_technique is not None:
        validate_techniques(args.mitre_technique)


###
# Main entry point.
###
def main():
    signal.signal(signal.SIGINT, sigint_handler)
    parser = init_argparse()
    args = parser.parse_args()

    additional_args_validation(args)

    t = Terminal()
    try:
        service = connect(args)
    except ConnectionRefusedError:
        log_error(
            f"Could not connect to {args.server} on tcp/{args.port}. Check the Splunk server is running and accessible on that port.")
        sys.exit(1)

    print(f"{t.bold}Getting status of previous ES Security Detections executions (KVStore)... {t.normal}", end='', flush=True)
    collection = get_detection_status_collection(args, service)
    print(f"{t.bold_green}{len(collection.data.query())} results read.{t.normal}")
    sleep(1)

    if args.reset:
        print(f"{t.bold}Resetting status of ES Security Detections (KVStore)... {t.normal}", end='', flush=True)
        collection.data.delete()
        print(f"{t.bold_green}done.{t.normal}")

    if args.list:
        list_results(collection, args, t)
    else:
        if args.schedule:
            schedule_detections(args, service, collection, t)
        else:
            execute_detections(args, service, collection, t)


if __name__ == "__main__":
    main()
