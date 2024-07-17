'''  # JSON Output
# Structure
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
      
# Example vuln

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
#

Patch Tuesday

Run. Automatic. Maybe bare vel å fyre skriptet kl 1600....
Maile når Release notes foreligger.
Sjekke tingen.

Er det noe ADV i listen? (Det var to i Jan2024)


MS har jo egen rating
Windows Authentication Methods	CVE-2024-20674	Windows Kerberos Security Feature Bypass Vulnerability	Critical
Windows Hyper-V	CVE-2024-20700	Windows Hyper-V Remote Code Execution Vulnerability	Critical
#
'''