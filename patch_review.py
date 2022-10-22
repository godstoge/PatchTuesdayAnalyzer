# PatchReview
# Source: Kevin Breen, Immersive Labs https://github.com/Immersive-Labs-Sec/msrc-api
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

'''  # JSON Output
 "Vulnerability": [
    {
      "Title": {},
      "Notes": [],
      "DiscoveryDateSpecified": false,
      "ReleaseDateSpecified": false,
      "CVE": "CVE-2022-21845",
      "ProductStatuses": [ ],
      "Threats": [],
      "CVSSScoreSets": [ ],
      "Remediations": [],
      "Acknowledgments": [],
      "Ordinal": "0",
      "RevisionHistory": [
        {
          "Number": "1.0",
          "Date": "2022-07-12T07:00:00",
          "Description": {
            "Value": "<p>Information published.</p>\n"
          }
        }
      ]
    },
    {
      "Title": {
        "Value": "Windows BitLocker Information Disclosure Vulnerability"
      },
      ...
	  

'''

# TODO
# Sort out highest CVSSseses by CVSS score
# --date 2022-jun has an unknown vuln
# august har  [-] CVE-2022-34303 - 0.0 - CERT/CC: CVE-20220-34303 Crypto Pro Boot Loader Bypass
# Create a webhook function
# Create arg to retrieve EEPS for the CVEs - could be fun for historical lookups (i.e. which of the CVEs 3 months ago are badness?)
# Iterate through all vulns to be printed to find the correct colwidth.
#       done    parser grab current month
#       done    Create check to ensure we have a match between our count and the number of vulns in the returned json.
#       done    Create function for RCE
#       done    Create table form (Team allow 117 characters wide before line break)
#       done    Create table form for all
#       done    Create arg to paste Link to CVE-site at MS.
import argparse
import requests
import re
from datetime import datetime
import sys # for argv
#import json

# Global variables
base_url = 'https://api.msrc.microsoft.com/cvrf/v2.0/'
headers = {'Accept': 'application/json'}
colwidth=0

vuln_types = [
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Remote Code Execution',
    'Information Disclosure',
    'Denial of Service',
    'Spoofing',
    'Edge - Chromium'
    ]


def count_type(search_type, all_vulns):
    counter = 0
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 0:
                if search_type == "Edge - Chromium":
                    if threat['ProductID'][0] == '11655':
                        counter += 1
                        break
                elif threat['Description'].get('Value') == search_type:
                    if threat['ProductID'][0] == '11655':
                        # Do not double count Chromium Vulns
                        break
                    counter += 1
                    break
        

    
    return counter

def count_exploited(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        cvss_score = 0.0
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0 :
            cvss_score = cvss_sets[0].get('BaseScore', 0.0)

        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                if 'Exploited:Yes' in description:
                    counter += 1
                    cves.append(f'{vuln["CVE"]} - {cvss_score} - {abbreviate_vuln(vuln["Title"]["Value"])}')
                    break
    return {'counter': counter, 'cves': cves}

def exploitation_likely(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        cvss_score = 0.0
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0 :
            cvss_score = cvss_sets[0].get('BaseScore', 0.0)
            
           
        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                if 'Exploitation More Likely'.lower() in description.lower():
                    counter += 1
                    cves.append(f'{vuln["CVE"]} - {cvss_score} - {abbreviate_vuln(vuln["Title"]["Value"])}')
                    break
    return {'counter': counter, 'cves': cves}

def list_out_rce(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        cvss_score = 0.0
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0 :
            cvss_score = cvss_sets[0].get('BaseScore', 0.0)

        for threat in vuln['Threats']:
            if threat['Type'] == 0:
                if threat['Description'].get('Value') == "Remote Code Execution":
                    cves.append(f'{vuln["CVE"]} - {cvss_score} - {abbreviate_vuln(vuln["Title"]["Value"])}')
                    counter += 1
                    break
    return {'counter': counter, 'cves': cves}
 
def list_highest_rated_vulns(supplied_all_vulns,supplied_base):
    base_score = supplied_base
    counter = 0
    cvesdetails = []  # CVEID - CVSS - Title
    for vuln in supplied_all_vulns:
        title = vuln.get('Title', {'Value': 'Not Found'}).get('Value')
        cve_id = vuln.get('CVE', '')
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0 :
            cvss_score = cvss_sets[0].get('BaseScore', 0)
            if cvss_score >= base_score:
                cvesdetails.append(f'{cve_id} - {cvss_score} - {abbreviate_vuln(title)}')
    return {'counter': counter, 'cves': cvesdetails}
                
def check_data_format(date_string):
    #check the date format is yyyy-mmm
    date_pattern = '\\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$'
    if re.match(date_pattern, date_string, re.IGNORECASE):
        return True

def print_header(title):
    print("[+] Microsoft Patch Tuesday Stats")
    print(f"[+] {title}")

def abbreviate_vuln(arg):
    # Function to abbreviate text such as 
    # "Windows Secure Socket Tunneling Protocol (SSTP) Remote Code Execution Vulnerability"
    # down to something like "Windows Secure Socket Tunneling Protocol (SSTP) RCE"
    if cliargs.noabb: 
        return arg
    #Replace text and return arg
    arg = arg.replace("Remote Code Execution Vulnerability","RCE")
    arg = arg.replace("Elevation of Privilege Vulnerability","EoP")
    arg = arg.replace("Security Feature Bypass Vulnerability","Security Feature Bypass")
    return arg

def insert_table_with_links(provided_cves):
    cvewithlink = []     
    global colwidth
    # Go through entire json file to find the longest title.
    if colwidth == 0:
        for entry in all_vulns:     
            if len(abbreviate_vuln(entry['Title']['Value'])) >= colwidth:
                colwidth = len(abbreviate_vuln(entry['Title']['Value']))
    else: 
        pass # Colwidth has already been determined.

    # Print stuff
    coloumns = str("{:<"+str(colwidth+31)+"}{:87}")  # Link is 87 characters long.
    for cve in provided_cves:
        cvewithlink.insert(0,"  [-] "+cve) 
        cvewithlink.insert(1,"https://msrc.microsoft.com/update-guide/en-US/security-guidance/advisory/"+cve.split()[0]) 
        print(coloumns.format(*cvewithlink))



if __name__ == "__main__":
    
    
    
    '''
 {
  "Title": {
    "Value": "Windows CSRSS Elevation of Privilege Vulnerability"
  },
  "Notes": [
    {
      "Title": "Description",
      "Type": 2,
      "Ordinal": "0"
    },
    {
      "Title": "FAQ",
      "Type": 4,
      "Ordinal": "10",
      "Value": "<p><strong>What privileges could an attacker gain?</strong></p>\n<p>An attacker who successfully exploited this vulnerability could gain SYSTEM privileges.</p>\n"
    },
    {
      "Title": "Windows Client/Server Runtime Subsystem",
      "Type": 7,
      "Ordinal": "20",
      "Value": "Windows Client/Server Runtime Subsystem"
    },
    {

 
    
    GOS: For ref:
    class apache_spark_cve_2022_33891_poc():
        def main(self, target_url, dnslog_url, file):
            session = requests.session()
            count = 0
    
    Gos: lag eget python-script med epss-class som kan importeres her (og brukes andre steder).
    '''
   
    # Parser action 
    
    parser = argparse.ArgumentParser(description='Read vulnerability stats for a patch tuesday release.')
    parser.add_argument('--date', help="Date string for the report query in format YYYY-mmm")
    parser.add_argument('--jsondump', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--noabb', action='store_true', help="No abbreviation of text. Handy for copy-pasting to whatever it is needed for.")
    parser.add_argument('--links', action='store_true', help="Also print links to CVEs.")
    cliargs = parser.parse_args()
    
    if cliargs.date:
        if not check_data_format(cliargs.date):
            print("[!] Invalid date format please use 'yyyy-mmm'")
            exit()
        else:
            date_to_fetch = cliargs.date
    else:
        print("[+] Print current months Patch Tuesday stats.")
        # Use manual month list as datetimes month abbreviation is based on running systems locale
        list_months = ["Bogus-place-holder","jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"]
        current_month = list_months[datetime.now().month] 
        date_to_fetch = str(datetime.now().year) + "-" + current_month
        

    # Get the list of all vulns
    get_sec_release = requests.get(f'{base_url}cvrf/{date_to_fetch}', headers=headers)
    if get_sec_release.status_code != 200:
        print(f"[!] Thats a {get_sec_release.status_code} from MS no release notes yet")
        print(f"[!] {base_url}cvrf/{date_to_fetch}")
        exit()

    release_json = get_sec_release.json()
    #print(json.dumps(release_json))
    title = release_json.get('DocumentTitle', 'Release not found').get('Value')
    all_vulns = release_json.get('Vulnerability', [])
    len_vuln = len(all_vulns)


# Handle debug args
    if cliargs.jsondump == 1:
        print(f'[+] --jsondump supplied.')
        print(f'[+] Printing raw JSON')
        print(all_vulns)
        exit()


# Print header
    print_header(title)

# Printing a summary of all vulnerabilities
    print(f'[+] Found a total of {len_vuln} vulnerabilities')
    itercount = 0
    for vuln_type in vuln_types:

        count = count_type(vuln_type, all_vulns)
        print(f'  [-] {count} {vuln_type} Vulnerabilities')
        itercount = itercount+count
    if len_vuln == itercount: pass
    else: 
        print(f'[!] ERROR - the summerization, {itercount} does not match the number of vulnerabilities {len_vuln} in the release notes. New vuln type?')
            
        # We are counting the number of entries in all_vulns match each entry of vuln_types. We add the different vulns together in itercount.
        # Now all_vulns does not match our itercount, which means there is a vulnerability in the release note which we have not 
        # listed in the list vuln_types[]
        
        
            # enumerate alle vulns i dict. CVE ID:undetermined
            #   for each cveID 
                #kjør gjennom count_type-logikk,men oppdater med CVEID:vulntype
    # sjekk om vuln_types finnes i listen.
    # if yes - ok. If no, raise something.
        cveid_vuln_dict = {}
        for vuln in all_vulns:
            # Enumerate all CVE ID in dict
            
            cveid_vuln_dict.update({vuln['CVE']:"undetermined"}) 
        
            for threat in vuln['Threats']:
                if threat['Type'] == 0:
                    if threat['Description'].get('Value') in  vuln_types:
                        if threat['ProductID'][0] == '11655':
                            # Do not double count Chromium Vulns
                            cveid_vuln_dict.update({vuln['CVE']:threat['Description'].get('Value')}) 
                            break
                        cveid_vuln_dict.update({vuln['CVE']:threat['Description'].get('Value')}) 
                        break
        print(len(cveid_vuln_dict))
        for key,value in cveid_vuln_dict.items():
            if value == "undetermined":
                print(key + " => " + value)
        

# Print exploited
    exploited_in_the_wild = count_exploited(all_vulns)
    print(f'[+] Found {exploited_in_the_wild["counter"]} exploited in the wild')

    if cliargs.links ==1: 
        # --Links has been provided. Therefor we use coloumns to display text.
        insert_table_with_links(exploited_in_the_wild['cves'])   
    else:
        for cve in exploited_in_the_wild['cves']:
            print(f'  [-] {cve}')

# Print Highest rated vulns 

    print('[+] Highest Rated Vulnerabilities')
    list_hrv = list_highest_rated_vulns(all_vulns,8.0)
   
    if cliargs.links ==1: 
        # --Links has been provided. Therefor we use coloumns to display text.
        insert_table_with_links(list_hrv['cves'])   
    else:
        for fullcvedetails in list_hrv['cves']:
            print(f'  [-] {fullcvedetails}')
            
#Print out likely to be exploited
    exploitation = exploitation_likely(all_vulns)
    print(f'[+] Found {exploitation["counter"]} vulnerabilites more likely to be exploited')
    
    
    if cliargs.links ==1: 
        # --Links has been provided. Therefor we use coloumns to display text.
        insert_table_with_links(exploitation['cves'])   
    else:
        for cve in exploitation['cves']:
            print(f'  [-] {cve}')
        
#Print out RCEs
    rces = list_out_rce(all_vulns)
    print(f'[+] Found {rces["counter"]} Remote Code Executions')
    #for cve in sorted(rces['cves'], key=str):
    #    print(f'  [-] {cve}')
    if cliargs.links ==1: 
        # --Links has been provided. Therefor we use coloumns to display text.
        insert_table_with_links(sorted(rces['cves'], key=str)) 
    else:
        for cve in rces['cves']:
            print(f'  [-] {cve}')
