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
      
{'Title': {'Value': 'Microsoft Office Information Disclosure Vulnerability'}, 
'Notes': [{'Title': 'Description', 'Type': 2, 'Ordinal': '0'}, {'Title': 'FAQ', 'Type': 4, 'Ordinal': '10', 'Value': '<p><strong>What type of information could be disclosed by this vulnerability?</strong></p>\n<p>The type of information that could be disclosed if an attacker successfully exploited this vulnerability is uninitialized memory.</p>\n'}, {'Title': 'FAQ', 'Type': 4, 'Ordinal': '10', 'Value': '<p><strong>Is the Preview Pane an attack vector for this vulnerability?</strong></p>\n<p>No, the Preview Pane is not an attack vector.</p>\n'}, {'Title': 'FAQ', 'Type': 4, 'Ordinal': '10', 'Value': '<p><strong>According to the CVSS metric, user interaction is required (UI:R). What interaction would the user have to do?</strong></p>\n<p>Exploitation of the vulnerability requires that a user open a specially crafted file.</p>\n<ul>\n<li>In an email attack scenario, an attacker could exploit the vulnerability by sending the specially crafted file to the user and convincing the user to open the file.</li>\n<li>In a web-based attack scenario, an attacker could host a website (or leverage a compromised website that accepts or hosts user-provided content) containing a specially crafted file designed to exploit the vulnerability.</li>\n</ul>\n<p>An attacker would have no way to force users to visit the website. Instead, an attacker would have to convince users to click a link, typically by way of an enticement in an email or instant message, and then convince them to open the specially crafted file.</p>\n'}, {'Title': 'Microsoft Office', 'Type': 7, 'Ordinal': '20', 'Value': 'Microsoft Office'}, {'Title': 'Microsoft', 'Type': 8, 'Ordinal': '30', 'Value': 'Microsoft'}], 
'DiscoveryDateSpecified': 0, 
'ReleaseDateSpecified': 0, 
'CVE': 'CVE-2023-21714', 
'ProductStatuses': [{'ProductID': ['11762', '11763', '11952', '11953'], 'Type': 3}], 
'Threats': [{'Description': 
				{'Value': 'Information Disclosure'}, 
				'ProductID': ['11762'], 
				'Type': 0, 
				'DateSpecified': 0}, 
			{'Description': {'Value': 'Information Disclosure'}, 'ProductID': ['11763'], 'Type': 0, 'DateSpecified': 0}, 
			{'Description': {'Value': 'Information Disclosure'}, 'ProductID': ['11952'], 'Type': 0, 'DateSpecified': 0}, 
			{'Description': {'Value': 'Information Disclosure'}, 'ProductID': ['11953'], 'Type': 0, 'DateSpecified': 0}, 
			{'Description': {'Value': 'Important'}, 'ProductID': ['11762'], 'Type': 3, 'DateSpecified': 0}, 
			{'Description': {'Value': 'Important'}, 'ProductID': ['11763'], 'Type': 3, 'DateSpecified': 0}, 
			{'Description': {'Value': 'Important'}, 'ProductID': ['11952'], 'Type': 3, 'DateSpecified': 0}, 
			{'Description': {'Value': 'Important'}, 'ProductID': ['11953'], 'Type': 3, 'DateSpecified': 0}, 
			{'Description': {'Value': 'Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely;DOS:N/A'}, 'Type': 1, 'DateSpecified': 0}], 
'CVSSScoreSets': [
	{'BaseScore': 5.5, 'TemporalScore': 4.8, 'Vector': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C', 'ProductID': ['11762']}, 
	{'BaseScore': 5.5, 'TemporalScore': 4.8, 'Vector': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C', 'ProductID': ['11763']}, 
	{'BaseScore': 5.5, 'TemporalScore': 4.8, 'Vector': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C', 'ProductID': ['11952']}, 
	{'BaseScore': 5.5, 'TemporalScore': 4.8, 'Vector': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C', 'ProductID': ['11953']}], 
'Remediations': [{'Description': {'Value': 'Click to Run'}, 'URL': '', 'ProductID': ['11762', '11763', '11952', '11953'], 'Type': 2, 'DateSpecified': 0, 'AffectedFiles': [], 'RestartRequired': {'Value': 'No'}, 'SubType': 'Security Update', 'FixedBuild': 'https://aka.ms/OfficeSecurityReleases'}], 
'Acknowledgments': [{'Name': [{'Value': 'willJ of vulnerability research institute'}], 'URL': ['']}], 
'Ordinal': '37', 'RevisionHistory': [{'Number': '1.0', 'Date': '2023-02-14T08:00:00', 'Description': {'Value': '<p>Information published.</p>\n'}}]}, 
      
      ...
	  
    For NIST så er Title bestandig tom.
    {   
        'Title': {},   
        'Notes': [
                {'Title': 'NIST NVD Details', 'Type': 6, 'Ordinal': '1', 'Value': 'https://nvd.nist.gov/vuln/detail/CVE-2023-0054'}, 
                {'Title': 'Description', 'Type': 2, 'Ordinal': '0'}, 
                {'Title': 'Mariner', 'Type': 7, 'Ordinal': '20', 'Value': 'Mariner'}, 
                {'Title': 'security@huntr.dev', 'Type': 8, 'Ordinal': '30', 'Value': 'security@huntr.dev'}], 
        'DiscoveryDateSpecified': False, 
        'ReleaseDateSpecified': False, 
        'CVE': 'CVE-2023-0054', 
        'ProductStatuses': [{'ProductID': ['12139', '12140'], 'Type': 3}], 
        'Threats': [{'Description': {}, 'ProductID': ['12139'], 'Type': 0, 'DateSpecified': False}, {'Description': {}, 'ProductID': ['12140'], 'Type': 0, 'DateSpecified': False}, {'Description': {}, 'ProductID': ['12139'], 'Type': 3, 'DateSpecified': False}, {'Description': {}, 'ProductID': ['12140'], 'Type': 3, 'DateSpecified': False}, {'Description': {'Value': 'DOS:N/A'}, 'Type': 1, 'DateSpecified': False}], 
        'CVSSScoreSets': [{'BaseScore': 7.8, 'TemporalScore': 7.8, 'Vector': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'ProductID': ['12139']}, {'BaseScore': 7.8, 'TemporalScore': 7.8, 'Vector': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'ProductID': ['12140']}], 
        'Remediations': [{'Description': {'Value': 'vim'}, 'URL': '', 'ProductID': ['12139', '12140'], 'Type': 2, 'DateSpecified': False, 'AffectedFiles': [], 'RestartRequired': {}, 'SubType': 'CBL-Mariner', 'FixedBuild': '9.0.1145-1'}], 
        'Acknowledgments': [], 
        'Ordinal': '8', 
        'RevisionHistory': 

    
{'Title': {}, 
'Notes': [
	{'Title': 'NIST NVD Details', 'Type': 6, 'Ordinal': '1', 'Value': 'https://nvd.nist.gov/vuln/detail/CVE-2022-43552'}, 
	{'Title': 'Description', 'Type': 2, 'Ordinal': '0'}, 
	{'Title': 'Mariner', 'Type': 7, 'Ordinal': '20', 'Value': 'Mariner'}, 
	{'Title': 'cve-assignments@hackerone.com', 'Type': 8, 'Ordinal': '30', 'Value': 'cve-assignments@hackerone.com'}], 
'DiscoveryDateSpecified': 0, 
'ReleaseDateSpecified': 0, 'CVE': 'CVE-2022-43552', 
'ProductStatuses': [{'ProductID': ['12139', '12140'], 'Type': 3}], 
'Threats': [
	{'Description': {}, 'ProductID': ['12139'], 'Type': 0, 'DateSpecified': 0}, 
	{'Description': {}, 'ProductID': ['12140'], 'Type': 0, 'DateSpecified': 0}, 
	{'Description': {}, 'ProductID': ['12139'], 'Type': 3, 'DateSpecified': 0}, 
	{'Description': {}, 'ProductID': ['12140'], 'Type': 3, 'DateSpecified': 0}, 
	{'Description': {'Value': 'DOS:N/A'}, 'Type': 1, 'DateSpecified': 0}], 
'CVSSScoreSets': [], 
'Remediations': [
	{'Description': {'Value': 'curl'}, 
	'URL': '',
	'ProductID': ['12139', '12140'], 
	'Type': 2, 
	'DateSpecified': 0, 
	'AffectedFiles': [], 
	'RestartRequired': {}, 
	'SubType': 'CBL-Mariner', 
	'FixedBuild': '7.86.0-3'}], 
'Acknowledgments': [], 
'Ordinal': '1', 
'RevisionHistory': [{'Number': '1.0', 'Date': '2023-02-10T00:00:00', 'Description': {'Value': '<p>Information published.</p>\n'}}]}
 
'''
'''
Gå gjennom hele release notes, 
    Sjekk antall entries i en release note > Gjør avsjekk; stemmer denne med dict når ferdig.
	Kartlegg CVEene i egen dict
		hent ut CVE IDer
		For CVE finn values in Threat (Remote Code Execution, EoP, osv) > Velg den som er mest bad
		Har CVE noe greier ift. FAQ need to do things? - yay, nay
		Er det en ADV -> Egen adv-dict

{
	'CVE': {'Value': 'CVExxxx'}
	'Title': {'Value': 'Windows Graphics Component Remote Code Execution Vulnerability'},
    'VulnerabilityType': {'Value': 'RCE'}
    'ExploitLikelihood': {'Value': 'xxxxx'}
	'CVSS': {'Value': '10.0'},
	'EEPS': {'Value': '0'},
    'FilteredFAQ': [{'FAQ1': 'xxxx'}
    'Directlink': {'Value': 'xxxxx'}  #Kanskje ikke applicable for alle.
	
	
		

'''
# TODO
# Script sjekk om CVE-nummer starter med ADV (Januar har 93 vuln mot 118 linjer). Noen er oppdatert, så annen release date, men oppdatering januar. 
# List out FAQs - Kanskje få ut alle FAQer - Det er jo som regel der det linkes til ADV og KB. Evt. gjøre sjekker på FAQer som ikke har boiler plate shit (Filtering by exemption) examples
    #"Are there additional steps that I need to take to be protected from this vulnerability?"
    #"How do I protect myself from this vulnerability?"
    # "Are any additional steps required to protect my SharePoint farm after installing the January 10, 2023 security update for SharePoint Server?"
    #  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21531
    # - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41099
    #  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21743
# Ta ut Security Feature Bypass Vulnerabilitys på lik linje med RCE, EoP, osv - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21759 - Var 4 i januar
# Kanskje lage en oneliner oversikt med ekstras  CVE - CVSS - Text - Calc - Exploitability (Public, Exploited, Likelyhood) - FAQ that's not boiler plate
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

headers = {'Accept': 'application/json'}
colwidth=0

vuln_types = [
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Remote Code Execution',
    'Information Disclosure',
    'Denial of Service',  
    'Spoofing',
    'Edge - Chromium',
    'DOS'
    ]


def count_type(search_type, all_vulns):
    counter = 0
    for vuln in all_vulns:
        #print(type(vuln['Notes']))
        for noteentries in vuln['Notes']: pass
            #if noteentries.get('Title') == "NIST NVD Details": print("Basj")
        for threat in vuln['Threats']:
            if threat['Type'] == 0:
                if search_type == "Edge - Chromium":
                    if threat['ProductID'][0] == '11655':
                        if "NIST" in vuln['Notes']: print("AYE")
                        counter += 1
                        #print(vuln["CVE"])
                        break
                elif threat['Description'].get('Value') == search_type:
                    #print(threat['Description'].get('Value'))
                    if threat['ProductID'][0] == '11655':
                # Do not double count Chromium Vulns
                        break
                    counter += 1 # Count current search type
                    if "NIST" in vuln['Notes']: print("AYE")
                    #print(vuln["CVE"])
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
            
           
        for threatentry in vuln['Threats']:
            if threatentry['Type'] == 1:
                description = threatentry['Description']['Value']
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
    if type(arg) == "NoneType":
        return arg
    #Replace text and return arg
    try:
        arg = arg.replace("Remote Code Execution Vulnerability","RCE")
        arg = arg.replace("Elevation of Privilege Vulnerability","EoP")
        arg = arg.replace("Security Feature Bypass Vulnerability","Security Feature Bypass")
    except:
        return arg
    return arg

def insert_table_with_links(provided_cves):
    cvewithlink = []     
    global colwidth
    # Go through entire json file to find the longest title.
    if colwidth == 0:
        for entry in all_vulns:     
            try:
                if len(abbreviate_vuln(entry['Title']['Value'])) >= colwidth:
                    colwidth = len(abbreviate_vuln(entry['Title']['Value']))
            except: pass
    else: 
        pass # Colwidth has already been determined.

    # Print stuff
    coloumns = str("{:<"+str(colwidth+31)+"}{:87}")  # Link is 87 characters long.
    for cve in provided_cves:
        cvewithlink.insert(0,"  [-] "+cve) 
        cvewithlink.insert(1,"https://msrc.microsoft.com/update-guide/en-US/security-guidance/advisory/"+cve.split()[0]) 
        print(coloumns.format(*cvewithlink))

def getReleaseNotes(date):
    # Get the list of all vulns and return a dict
    base_url = 'https://api.msrc.microsoft.com/cvrf/v2.0/'
    get_sec_release = requests.get(f'{base_url}cvrf/{date}', headers=headers)
    if get_sec_release.status_code != 200:
        print(f"[!] Thats a {get_sec_release.status_code} from MS no release notes yet")
        print(f"[!] {base_url}cvrf/{date}")
        exit()
    
    releaseNotes_JSON = get_sec_release.json()
    return releaseNotes_JSON

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
        current_month = list_months[datetime.now().month]   # DEBUG  DEBUG  DEBUG  DEBUG  DEBUG 
        #current_month = list_months[datetime.now().month] 
        date_to_fetch = str(datetime.now().year) + "-" + current_month


    '''
    all_vulns = releaseNotes_JSON.get('Vulnerability', [])
    for 
    numberOfVulnerabilities = len(all_vulns)
    '''
        
    '''
    for rawvuln in all_vulns_raw:
            if rawvuln['Title']:
                #print(type(rawvuln))
                #print(type(rawvuln['Notes']))                #{'Title': 'Description', 'Type': 2, 'Ordinal': '0', 'Value': '<p>This CVE was assigned by Chrome
                all_vulns.append(rawvuln)
                #print(rawvuln['Title'])'''
    
    releaseNotes = getReleaseNotes(date_to_fetch)
    title = releaseNotes.get('DocumentTitle', 'Release not found').get('Value')
    all_vulns = [] #dict
    all_vulns = releaseNotes.get('Vulnerability', [])   # list
    numberOfVulnerabilities = len(all_vulns)


# Handle debug args
    if cliargs.jsondump == 1:
        print(f'[+] --jsondump supplied.')
        print(f'[+] Printing raw JSON')
        print(all_vulns)
        exit()


# Print header
    print_header(title)

# Printing a summary of all vulnerabilities
    print(f'[+] Found a total of {numberOfVulnerabilities} vulnerabilities')
    itercount = 0
    for vuln_type in vuln_types:

        count = count_type(vuln_type, all_vulns)
        print(f'  [-] {count} {vuln_type} Vulnerabilities')
        itercount = itercount+count
    if numberOfVulnerabilities == itercount: pass
    else: 
        print(f'[!] ERROR - the summerization, {itercount} does not match the number of vulnerabilities {numberOfVulnerabilities} in the release notes. New vuln type?')
            
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

    print('[+] Highest Rated Vulnerabilities (i.e. 8.0 and above)')
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
