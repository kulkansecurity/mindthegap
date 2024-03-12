# Mind The Gap

Mind The Gap is a Python-based tool specifically designed for users to identify the "patch gap" in their Ubuntu release - the delay between the disclosure of a vulnerability and the patch release. By querying Ubuntu's CVE system, it provides a clearer picture of the current security standing of different Ubuntu versions.

More on Ubuntu's patch gap and an introduction to Mind The Gap is available at:
https://blog.kulkan.com/

![MindTheGap](screencapture.png?raw=true "MindTheGap")

## Introduction

In the dynamic world of software vulnerabilities, staying ahead of attackers is crucial. Mind The Gap was developed out of a personal experience with a vulnerability that was re-discovered although it had already been patched. This tool aims to highlight the patch gap in Ubuntu systems, providing users with actionable data to mitigate risks.

## Key Features:

- **CVE Reporting**: Prints out active Common Vulnerabilities and Exposures (CVEs) for a given Ubuntu version along with the number of days elapsed since their publication.

- **Patch Gap Statistics**: Provides basic statistics on the Patch Gap, helping users understand the security posture of their systems.

- **Customizable Filters**: Supports command-line tweaks to focus on specific priorities (e.g., critical, high) or statuses (e.g., needs-triage, needed, pending).

## Prerequisites:

- Python 3.x
- \`requests\` Python package

## Installation:

1. Clone this repository or download \`mindthegap.py\`.
2. Install the necessary Python packages:
   ```
   pip install requests
   ```

## Usage:

Here is how to use Mind The Gap:

1. To check active CVEs for the current Ubuntu version:
   ```
   ./mindthegap.py
   ```

2. To specify an Ubuntu version:
   ```
   ./mindthegap.py -version [version_codename]
   ```

3. To focus on specific priorities or statuses:
   ```
   ./mindthegap.py -priority critical -status released
   ```

4. For a silent mode that prints only stats:
   ```
   ./mindthegap.py -silent
   ```

5. To include CVE descriptions in the output:
   ```
   ./mindthegap.py -description
   ```

A few sample screen captures:
![MindTheGap](screencapture1.png?raw=true "MindTheGap")
![MindTheGap](screencapture2.png?raw=true "MindTheGap")

## Disclaimer:

- Mind The Gap was developed for educational and security assessment purposes. Do not use this tool for illegal activities.

## Acknowledgments:

- The Ubuntu security team for maintaining the CVE database and a transparent process:
 https://ubuntu.com/security/cves - https://code.launchpad.net/ubuntu-cve-tracker

