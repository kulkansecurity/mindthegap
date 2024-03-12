# 03-12-2024: Initial release of mindthegap.py
import requests
import argparse
import time  
import os
from datetime import datetime

def get_ubuntu_codename():
    if os.path.isfile('/etc/lsb-release'):
        with open('/etc/lsb-release') as f:
            lines = f.readlines()
            release_info = {}
            for line in lines:
                key, value = line.strip().split('=', 1)
                release_info[key] = value

            if release_info.get('DISTRIB_ID', '') == 'Ubuntu':
                return release_info.get('DISTRIB_CODENAME', 'Unknown version')
            else:
                raise Exception('Not Ubuntu')
    else:
        raise Exception('Not Ubuntu or /etc/lsb-release not found')


def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    percent = "{0:.1f}".format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end="\r", flush=True)
    if iteration == total: 
        print()

def fetch_vulnerabilities(package='', priority='', status='', version=''):
    base_url = 'https://ubuntu.com/security/cves.json'
    all_cves = []
    offset = 0
    limit = 40
    total_results = None
    while True:
        status_params = status.split(',') if status else []
        params = {
            'package': package,
            'priority': priority,
            'q': '',
            'version': version,
            'limit': limit,
            'offset': offset
        }
        if status_params:
            params['status'] = status_params
        else:
            params['status'] = ''

        response = requests.get(base_url, params=params)#, verify=False)
        if response.status_code == 200:
            data = response.json()

            all_cves.extend(data['cves'])
            if len(all_cves) == 0:
                print(f'No results found.')
                return all_cves

            if total_results is None:
                total_results = data['total_results']
                print(f'\rTotal results to fetch: {total_results} - Fetching groups of {limit}')
            print_progress_bar(len(all_cves), total_results, prefix='Progress:', suffix='Complete', length=50)
            time.sleep(0.1)  
            if len(all_cves) >= total_results:
                break
            else:
                offset += data['limit']
        else:
            print(f'\nFailed to retrieve data, status code: {response.status_code}')
            break
    return all_cves


def main():

    priorities = ['critical', 'high', 'medium', 'low', 'negligible']


    parser = argparse.ArgumentParser(description="Fetch Ubuntu CVEs")
    parser.add_argument('-package', help="Package name", default='')
    parser.add_argument('-priority', help="Priority " + str(priorities), choices=priorities)
    parser.add_argument('-status', help="Status (needs-triage, DNE, not-affected, needed, deferred, ignored, pending, released)", choices=['needs-triage', 'DNE', 'not-affected', 'needed', 'deferred', 'ignored', 'pending', 'released'])
    parser.add_argument('-version', help="Ubuntu version codename", choices=['jammy', 'noble', 'mantic', 'lunar', 'kinetic','impish','hirsute','groovy','focal','eoan','disco','cosmic','bionic','artful','zesty','yakkety','xenial','wily','vivid','utopic','trusty'])
    parser.add_argument('-patchgap', help="Override the status parameter and set status to needs-triage, needed, pending", action='store_true') 
    parser.add_argument('-description', help="Include the CVE description in the output", action='store_true')  
    parser.add_argument('-silent', help="Do not list the CVEs, just print stats", action='store_true')  

    args = parser.parse_args()

    print("""
    |\/|. _  _|  _|_|_  _    _  _  _ 
    |  ||| |(_|   | | |(/_  (_|(_||_)
                             _|   | 

    PoC for identifying the Patch Gap in Ubuntu releases
    v1.0 - Kulkan Security

    """)



    if args.patchgap and args.status:
        raise ValueError("Cannot use -status and -patchgap parameters simultaneously.")  

    if not args.patchgap and not args.status:
        # If no status is provided just turn on the patchgap behavior.
        args.patchgap = True

    if not args.version:
        try:
            args.version = get_ubuntu_codename()
            print(f"Version not specified. Using local Ubuntu version instead. Detected codename: {args.version}")
        except Exception as ex:
            print(ex)
            print('Unable to determine the local version of Ubuntu. Consider supplying a value in the "version" parameter. Exiting..')
            exit()
    else:
        print(f"Version specified. Filtering query results based on codename: {args.version}")

    if args.patchgap:
        print(f"PatchGap behavior enabled. Querying multiple active statuses. You can override with -status [status]")
        args.status = 'needed,pending,deferred'

    if args.description:
        print("Including CVE descriptions in the output")
    else:
        print("Not including CVE descriptions in the output. To include them, use -description")

    if args.priority:
        print(f"Filtering based on priority {args.priority}")
    else:
        print("Including all priorities, from critical to negligible. To filter by priority, use -priority [priority]")

    if args.silent:
        print("Silent mode active - not printing each individual CVE on screen, just sticking to printing stats")
    else:
        print("Listing each CVE on screen as well as stats. To print stats only use -silent")


    vulnerable_packages = {key: [] for key in priorities}
    gap_days = {key: [] for key in priorities}
    
    for status in args.status.split(','):
        print("")
        filter_package = args.package if args.package else "[all]"
        filter_priority = args.priority if args.priority else "[all]"
        filter_status = status
        filter_version = args.version if args.version else "[all]"
        print(f'Searching with query filters: package:{filter_package}, priority:{filter_priority}, status:{filter_status}, version:{filter_version}')
        print("Please wait..", end='', flush=True)
        results = fetch_vulnerabilities(package=args.package, priority=args.priority, status=status, version=args.version)
        print("")

        for cve in results:
            packages = cve.get('packages', [])
            for pkg in packages:
                for release_status in pkg.get('statuses', []):
                    cname = release_status['release_codename']
                    if cname != args.version:
                        continue
             
                    vulnerable_packages[cve.get('priority')].append(pkg['name'])
                    input_date = datetime.strptime(cve['published'], '%Y-%m-%dT%H:%M:%S')
                    elapsed_time = datetime.now() - input_date
                    gap_days[cve.get('priority')].append(elapsed_time.days)
                    description = cve.get('description','No description').replace('\n',' ')
                    if not args.silent: 
                        print(f"CVE ID: {cve.get('id', 'N/A')} - Vulnerable Package: {pkg['name']} - Priority: {cve['priority']}")
                        print(f"Status: {release_status['status']} -  Published: {cve['published']} - {elapsed_time.days} Days ago")
                        if args.description: 
                            print(f"{description}")
                        print("-" * 100)


    all_vulnerable_packages = [pkg for sublist in vulnerable_packages.values() for pkg in sublist]
    unique_all_vp = list(set(all_vulnerable_packages))
    all_gap_days = [days for sublist in gap_days.values() for days in sublist]
    if len(all_vulnerable_packages) == 0:
        print("No results obtained. Exiting..")
        return

    for priority in priorities:
        vp = vulnerable_packages[priority]
        unique_vp = list(set(vp))
        gd = gap_days[priority]
        if sum(gd) == 0:
            continue
        print(f"Unique list of {len(unique_vp)} vulnerable packages with {priority} priority active CVEs is: " + str(unique_vp))
        print("")
        print(f"There are {len(vp)} active combinations of CVE+package of {priority} priority.")
        print(f"The oldest {priority} priority active CVE has been published {max(gd)} days ago.")
        print(f"The newest {priority} priority active CVE has been published {min(gd)} days ago.")
        average = "{:.2f}".format(sum(gd) / len(gd))
        print(f"In average, the gap is of {average} days.")
        print("-" * 100)

    if not args.priority:
        print("")
        print(f"Across all priorities, the unique list of {len(unique_all_vp)} vulnerable packages is: " + str(unique_all_vp))
        print("")
        print(f"There are {len(all_vulnerable_packages)} active combinations of CVE+package across all priorities.")
        print(f"The oldest active CVE has been published {max(all_gap_days)} days ago.")
        print(f"The newest active CVE has been published {min(all_gap_days)} days ago.")
        average = "{:.2f}".format(sum(all_gap_days) / len(all_gap_days))
        print(f"In average, the gap is of {average} days.")

       

if __name__ == "__main__":
    main()



