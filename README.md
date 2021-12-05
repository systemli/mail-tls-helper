# mail-tls-helper

[![Build Status](https://travis-ci.org/systemli/mail-tls-helper.svg?branch=master)](https://travis-ci.org/systemli/mail-tls-helper)

Postfix helper script that does the following:

 * make TLS mandatory for outgoing mail wherever possible and
 * optionally alert postmasters of domains that don't support STARTTLS

In case of bugs, ideas, enhancements, feel free to open an *issue* or *pull
request* on Github.

## Prerequisites

 * Set *Postfix SMTP client logging* (configuration option
   [smtp_tls_loglevel](http://www.postfix.org/postconf.5.html#smtp_tls_loglevel))
   to '1' or higher.
 * Ensure that Python3 is installed.
 * Copy the script to your mail system (e.g. to ```/usr/local/bin/```) and make
   executable.
 * Make sure that the script can write to *Postfix TLS policy map* and *notls
   SQLite DB* and that the directories exist.

# *Postfix TLS policy map* Configuration

 * Configure the *Postfix TLS policy map* in ```main.cf```:
 
```smtp_tls_policy_maps = hash:/etc/postfix/tls_policy```

# Running the script

 * Run ```mail-tls-helper.py -h``` and learn about the commandline options.
 * Optionally configure logrotate to run the script automatically against the
   mail log file just after rotation. This can be done by configuring a
   ```post-script``` in the corresponding *logrotate configure include*
   (e.g. ```/etc/logrotate.d/rsyslog```):

```
/var/log/mail.log
{
	[...]
	postrotate
		[...]
		/usr/local/bin/mail-tls-helper.py -d example.org
	endscript
}
```

# Monitoring

* [munin](https://munin-monitoring.org): see the documentation header of `munin-plugin`


## Changelog

* 2018-07-18: version 0.9.0
  * added monitoring of mails sent over Tor
  * added reporting of blocked domains, because of missing TLS
  * added munin plugin
  * added tests
  * improved file handling
  * improved Python 3 compatibility
* 2017-11-11: version 0.8.1
  * fix version number and update todo list in the script
* 2017-11-11: version 0.8.0
  * restructured code, swap out all postfix related code into separate
    functions.
  * added new data structure 'relayDict' which can be filled by any
    mta specific functions
  * simplified the logic for parsing postfix logs
  * added IPv6 localhost address ::1 to relay whitlist
  * TLS domains are deleted from SQLite DB now
  * fixed calculated numbers of unencrypted mails
* 2017-06-04: version 0.7.3
  * add support for a relay whitelist
* 2017-06-04: version 0.7.2
  * set envelope sender address to op['from'] when using sendmail.
* 2017-05-18: version 0.7.1
  * don't send alert mails by default (Fixes #6)
  * consequently replace commandline options '-A'/'--no-alerts' by
    '-a'/'--alerts'.
* 2017-02-19: version 0.7
  * renamed to ```mail-tls-helper```
  * complete rewrite in Python
  * fixed logfile parsing logic, much more robust now
  * added support for commandline arguments
  * added support to create a Postfix TLS policy map
* 2017-01-22: version 0.5
  * initial release
