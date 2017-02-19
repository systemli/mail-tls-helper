# mail-tls-helper

Postfix helper script that does the following:

 * make TLS mandatory for outgoing mail wherever possible and
 * alert postmasters of mailservers that don't support STARTTLS

In case of bugs, ideas, enhancements, feel free to open an *issue* or *pull
request* on Github.

## Prerequisites

 * Set *Postfix SMTP client logging* (configuration option
   [smtp_tls_loglevel](http://www.postfix.org/postconf.5.html#smtp_tls_loglevel))
   to '1' or higher.
 * Ensure that Python (2.7) is installed.
 * Copy the script to your mail system (e.g. to ```/usr/local/bin/```) and make
   executable.
 * Make sure that the script can write to *Postfix TLS policy map* and *notls
   SQLite DB* and that the directories exist.

# *Postfix TLS policy map* Configuration

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

## Changelog

* 2017-02-19: version 0.7
  * renamed to ```mail-tls-helper```
  * complete rewrite in Python
  * fixed logfile parsing logic, much more robust now
  * added support for commandline arguments
  * added support to create a Postfix TLS policy map
* 2017-01-22: version 0.5
  * initial release
