# AsianBank

AsianBank is an automated phishing email analysis tool based on [TheHive](https://github.com/TheHive-Project/TheHive), [Cortex](https://github.com/TheHive-Project/Cortex/) and [MISP](https://github.com/MISP/MISP). It is a web application written in Python 3 and based on Flask that automates the entire analysis process starting from the extraction of the observables from the header and the body of an email to the elaboration of a verdict which is final in most cases. In addition, it allows the analyst to intervene in the analysis process and obtain further details on the email being analyzed if necessary. In order to interact with TheHive and Cortex, it uses [TheHive4py](https://github.com/TheHive-Project/TheHive4py) and [Cortex4py](https://github.com/TheHive-Project/Cortex4py), which are the Python API clients that allow using the REST APIs made available by TheHive and Cortex respectively.

![OS](https://img.shields.io/badge/OS-Linux-red?style=flat&logo=linux)
[![made-with-python](https://img.shields.io/badge/Made%20with-Python%203.8-1f425f.svg?logo=python)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-available-green.svg?style=flat&logo=docker)](https://github.com/emalderson/ThePhish/tree/master/docker)
[![Maintenance](https://img.shields.io/badge/Maintained-yes-green.svg)](https://github.com/emalderson/ThePhish)
[![GitHub](https://img.shields.io/github/license/emalderson/ThePhish)](https://github.com/emalderson/ThePhish/blob/master/LICENSE)
[![Documentation](https://img.shields.io/badge/Documentation-complete-green.svg?style=flat)](https://github.com/emalderson/ThePhish)

## Table of contents

* [Overview](#overview)
  + [The analyst analyzes the email](#the-analyst-analyzes-the-email)
* [Configure the analyzers](#configure-the-analyzers)
  + [Configure the levels of the analyzers](#configure-the-levels-of-the-analyzers)
  + [Tested analyzers](#tested-analyzers)
  + [Enable the *MISP* analyzer](#enable-the-misp-analyzer)
  + [Enable the *Yara* analyzer](#enable-the-yara-analyzer)
* [Enable the *Mailer* responder](#enable-the-mailer-responder)
* [Use the whitelist](#use-the-whitelist)
## Overview

The following diagram shows how AsianBank works at high-level:

 1. An attacker starts a phishing campaign and sends a phishing email to a user.
 2. A user who receives such an email can send that email as an attachment to the mailbox used by AsianBank.
 3. The analyst interacts with AsianBank and selects the email to analyze.
 4. AsianBank extracts all the observables from the email and creates a case on TheHive. The observables are analyzed thanks to Cortex and its analyzers.
 5. AsianBank calculates a verdict based on the verdicts of the analyzers.
 6. If the verdict is final, the case is closed and the user is notified. In addition, if it is a malicious email, the case is exported to MISP.
 7. If the verdict is not final, the analyst's intervention is required. He must review the case on TheHive along with the results given by the various analyzers to formulate a verdict, then he can send the notification to the user, optionally export the case to MISP and close the case.


## AsianBank example usage

This example aims to demonstrate how a user can send an email to ThePhish for it to be analyzed and how an analyst can actually analyze that email using AsianBank.

### A user sends an email to AsianBank

A user can send an email to the email address used by AsianBank to fetch the emails to analyze. The email has to be forwarded as an attachment in EML format so as to prevent the contamination of the email header. In this case, the used mail client is Mozilla Thunderbird and the used email address is a Gmail address.

### The analyst analyzes the email

The analyst navigates to the web page of AsianBank and clicks on the "List emails" button to obtain the list of emails to analyze.

When the analyst clicks on the "Analyze" button related to the selected email, the analysis is started and its progress is shown on the web interface.

In the meantime, AsianBank extracts the observables (URLs, domains, IP addresses, email addresses, attachments and hashes of those attachments) from the email and then interacts with TheHive to create the case.

Three tasks are created inside the case.

Then, AsianBank starts adding the extracted observables to the case.

At this point the user is notified via email that the analysis has started thanks to the *Mailer* responder.

The description of the first task allows the *Mailer* responder to send the notification via email.

After the first task is closed, the second task is started and the analyzers are started on the observables. The analysis progress is shown on the web interface while the analyzers are started.

The analysis progress can also be viewed on TheHive, thanks to its live stream.

Once all the analyzers have terminated their execution, the second task is closed and the third one is started, then AsianBank calculates the verdict. Since the verdict is "malicious", all the observables that are found to be malicious are marked as IoC. In this case only one observable is marked as IoC.

The case is then exported to MISP as an event, with a single attribute represented by the observable mentioned above. 

Then, AsianBank sends the verdict via email to the user thanks to the *Mailer* responder.

Finally, both the task and the case are closed. The description of the third task allows the *Mailer* responder to send the verdict via email. Moreover, the case has been closed after five minutes and resolved as "True Positive" with "No Impact", which means that the attack has been detected before it could do any damage.

Once the case is closed, the verdict is available for the analyst on the web interface together with the entire log of the analysis progress.

At this point the analyst can go back and analyze another email. The above-depicted case was related to a phishing email, but a similar workflow can be observed when the analyzed email is classified as "safe". Indeed, the case is closed and the verdict is sent via email to the user.

Then, the verdict is also displayed to the analyst on the web interface.

On the other hand, when an email is classified as "suspicious", the verdict is only displayed to the analyst on the web interface.
	
At this point the analyst needs to use the buttons on the left-hand side of the page to use TheHive, Cortex and MISP for further analysis. This is because the analysis has not been completed yet and so the user is only notified that the analysis of the email that he forwarded to AsianBank has been started. Indeed, the last task and the case have not been closed yet since they need to be closed by the analyst himself once he elaborates a final verdict. 

The analyst can view the reports of all the analyzers on TheHive and Cortex and, in case this revealed not to be enough, he could also download the EML file of the email and analyze it manually.

When the analyst terminates the analysis, he can populate the body of the email to send to the user in the description of the last task, start the *Mailer* responder, export the case to MISP if the verdict is "malicious" by clicking on the "Export" button and then close the case.


## Configure the analyzers

AsianBank can start an analyzer or a responder only if it is enabled and correctly configured on Cortex. [This](https://github.com/TheHive-Project/CortexDocs/blob/master/admin/admin-guide.md#organizations-users-and-analyzers) part of the documentation explains how to enable them, while [this](https://github.com/TheHive-Project/CortexDocs/blob/master/analyzer_requirements.md) part lists the available analyzers and responders with their configuration parameters. It should be noted that while many analyzers are free to use, some require special access and others necessitate a valid service subscription or product license.

### Configure the levels of the analyzers

Each analyzer outputs a report in JSON format that contains a maliciousness level for an observable that can be one of "info", "safe", "suspicious" or "malicious". However, even though the report structure usually follows a convention, this convention is not always respected. Moreover, after the analysis of the code of many analyzers and several tests, some analyzers have been found to contain bugs. For this reason, some tweaks and workarounds have been used either to obtain the maliciousness levels provided by these analyzers anyway or to prevent the application from crashing due to those bugs.

Furthermore, these levels do not always represent the real maliciousness level of an observable. Since this depends on how the analyzers themselves have been programmed, AsianBank comes with another configuration file called `analyzers_level_conf.json`, with which it is possible to create a mapping between the actual maliciousness levels provided by any analyzer and the levels decided by the analyst. Besides that, this file allows the analyst to choose what are the observable types to which these modifications should be applied. The file needs to follow the structure shown in the example here, using the exact name of the analyzers to configure and with the desired level on the right. If an analyzer is not listed in this file, then the maliciousness levels it provides are left untouched. The file needs to follow the structure shown in the following example, using the exact name of the analyzers to configure and with the desired level on the right. If an analyzer is not listed in this file, then the maliciousness levels it provides are left untouched.

```json
{
	"DomainMailSPFDMARC_Analyzer_1_1" : {
		"dataType" : ["url", "ip", "domain", "mail"],
		"levelMapping" : {
			"malicious" : "suspicious",
			"suspicious" : "suspicious",
			"safe" : "safe",
			"info" : "info"
		}
	},
	"MISP_2_1" : {
		"dataType" : ["url", "ip", "domain", "mail"],
		"levelMapping" : {
			"malicious" : "malicious",
			"suspicious" : "malicious",
			"safe" : "safe",
			"info" : "info"
		}
	},
	"VirusTotal_GetReport_3_0" : {
		"dataType" : ["ip", "domain"],
		"levelMapping" : {
			"malicious" : "info",
			"suspicious" : "info",
			"safe" : "safe",
			"info" : "info"
		}
	}
}
```

In this example, the level "suspicious" for the *MISP_2_1* analyzer is raised to "malicious" since it indicates that some observables in the email being currently analyzed have already been sighted in a previously analyzed email for which the verdict was "malicious". Conversely, the level "malicious" of the *DomainMailSPFDMARC_Analyzer_1_1* analyzer is lowered to "suspicious", since many legitimate domains do not have DMARC and SPF records configured. Moreover, the levels "suspicious" and "malicious" given by the *VirusTotal_GetReport_3_0* analyzer for IP addresses and domains are lowered to "info" since they have been observed to lead to lots of false positives. 

You can add or remove analyzers in this file at your will, but I recommend that you leave the ones that are already present in the file untouched since those modifications have been motivated by many tests performed on a lot of different emails.

### Tested analyzers
AsianBank has been tested with the following analyzers:
- AbuseIPDB_1_0
- AnyRun_Sandbox_Analysis_1_0
- CyberCrime-Tracker_1_0
- Cyberprotect_ThreatScore_3_0
- *DomainMailSPFDMARC_Analyzer_1_1*
- DShield_lookup_1_0
- EmailRep_1_0
- FileInfo_8_0
- Fortiguard_URLCategory_2_1
- IPinfo_Details_1_0
- **IPVoid_1_0** 
- Maltiverse_Report_1_0
- *Malwares_GetReport_1_0* 
- *Malwares_Scan_1_0*
- MaxMind_GeoIP_4_0 
- MetaDefenderCloud_GetReport_1_0
- *MISP_2_1*
- *Onyphe_Summary_1_0*
- OTXQuery_2_0
- PassiveTotal_Enrichment_2_0 
- *PassiveTotal_Malware_2_0* 
- PassiveTotal_Osint_2_0 
- PassiveTotal_Ssl_Certificate_Details_2_0 
- PassiveTotal_Ssl_Certificate_History_2_0 
- PassiveTotal_Unique_Resolutions_2_0 
- PassiveTotal_Whois_Details_2_0 
- PhishTank_CheckURL_2_1
- **Pulsedive_GetIndicator_1_0**
- *Robtex_Forward_PDNS_Query_1_0*
- *Robtex_IP_Query_1_0* 
- *Robtex_Reverse_PDNS_Query_1_0*
- Shodan_DNSResolve_1_0 
- **Shodan_Host_1_0** 
- **Shodan_Host_History_1_0**
- Shodan_InfoDomain_1_0 
- **SpamhausDBL_1_0**
- StopForumSpam_1_0
- *Threatcrowd_1_0*	
- UnshortenLink_1_2
- **URLhaus_2_0** 
- Urlscan_io_Scan_0_1_0 
- *Urlscan_io_Search_0_1_1* 
- *VirusTotal_GetReport_3_0*
- VirusTotal_Scan_3_0 
- Yara_2_0

The analyzers emphasized in *italic* are the ones for which the levels have been modified (but that can be overridden, even though it is not advisable), while the analyzers emphasized in **bold** are the ones that are handled directly in the code of AsianBank either because they do not respect the convention for the report structure, or because they have bugs. Moreover, the following analyzers are handled in the code of ThePhish to use them in the best possible manner:

- **DomainMailSPFDMARC_Analyzer_1_1**: It is started only on domains that are supposed to be able to send emails.
	
- **MISP_2_1**: It is used for the integration with MISP.
   
- **UnshortenLink_1_2**: It is started before any other analyzer on a URL so as to make it possible to unshorten a link and add the unshortened link as an additional observable.
  
- **Yara_2_0**: It is the only one that is started on the EML attachment.


### Enable the *MISP* analyzer

In order to integrate Cortex with MISP, you must activate the *MISP_2_1* analyzer and configure it with the authentication key of the user created on MISP that Cortex will use to interact with MISP. This means that an organization and a user with `sync_user` role in that organization must be created on MISP beforehand (you can learn how to do that and obtain the authentication key [here (AsianBank documentation, recommended)](https://github.com/emalderson/ThePhish/tree/master/docker#configure-the-misp-container) or [here (MISP documentation)](https://www.circl.lu/doc/misp/administration/#users).

### Enable the *Yara* analyzer

If you want to use the *Yara_2_0* analyzer, you must create a folder on the machine on which Cortex is running that contains:

 - The Yara rules, where each rule is a file with the `.yar` extension
 - A file named `index.yar`, which contains a line for each Yara rule in that folder that respects this syntax: `include "yara_rule_name.yar"`

Then, you must configure the path of this folder on Cortex. For example, if you created the folder `yara_rules` in the path `/opt/cortex`, then you need to configure the path `/opt/cortex/yara_rules` on Cortex (on the web interface).

## Enable the *Mailer* responder

In order to send the emails to the users, the *Mailer* responder must be enabled and correctly configured. The procedure used to enable a responder is identical to the procedure used to enable an analyzer. If you are using a Gmail address, these are the correct parameters to set:
- from: `<YourGmailEmailAddress>`
- smtp_host :`smtp.gmail.com`
- smtp_port: `587`
- smtp_user: `<YourGmailEmailAddress>`
- smtp_pwd: `<YourGmailEmailAddressAppPassword>`


## Use the whitelist

AsianBank allows creating a whitelist in order to avoid analyzing observables that may cause false positives or that the analyst decides that they should not be considered during the analysis. The whitelist is contained in a file named `whitelist.json` and is constituted by many different lists so as to offer great flexibility both in terms of observable types to match and matching modes. It supports the following matching modes:

 - Exact string matching for email addresses, IP addresses, URLs, domains, file names, file types and hashes
 - Regex matching for email addresses, IP addresses, URLs, domains and file names
 - Regex matching for subdomains, email addresses and URLs that contain the specified domains


Here is shown a toy example of the `whitelist.json` file.

```json
{	
	"exactMatching": {
		"mail" : [],
		"ip" : [
			"127.0.0.1",
			"8.8.8.8",
			"8.8.4.4"
		],
		"url" : [],
		"domain" : [
			"adf.ly",
			"paypal.com"
		],
		"filename" : [],
		"filetype" : [
			"application/pdf"
		],
		"hash" : []
	},
	"domainsInSubdomains" : [
		"paypal.com"
	],
	"domainsInURLs" : [
		"paypal.com"
	],
	"domainsInEmails" : [
		"paypal.com"
	],
	"regexMatching" : {
		"mail" : [],
		"ip" : [
			"10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
			"172\\.16\\.\\d{1,3}\\.\\d{1,3}",
			"192\\.168\\.\\d{1,3}\\.\\d{1,3}"
		],
		"url" : [],
		"domain" : [],
		"filename" : []
	}
}
```

While both the parts related to exact matching and regex matching are used without any modification, the remaining parts are used to create three more lists of regular expressions. It is not required for you to design complex regular expressions to enable those features, but you only need to add the domains to the right lists and AsianBank will do the rest. For instance, in the example shown above, not only the domain "paypal&#46;com" is filtered, but any subdomain, URL and email address containing the domain "paypal&#46;com" is filtered as well. These regular expressions have been designed to avoid some unwanted behaviors, for instance they prevent domains like "paypal&#46;com&#46;attacker&#46;com" to be mistakenly whitelisted.
The whitelist file which is provided in this repository is already populated with some whitelisted observables, but it is just an example, you can (and should) edit it to suit your needs by removing or adding elements.
