# check-notls-mailservers

Script to check for outgoing mail that is not transport-encrypted

* The script parses the Postfix mail log for outgoing mail that is not
  transport-encrypted via TLS and gives a summary with some stats.
* Optionally the script sends alert mails to the postmasters of receiving
  mailserver without STARTTLS support.

In case of bugs, ideas, enhancements, feel free to open an *issue* or *pull
request* on Github.

## How to use this script

* In order to work, this script needs *Postfix SMTP client logging*
  (configuration option [smtp_tls_loglevel](http://www.postfix.org/postconf.5.html#smtp_tls_loglevel))
  to be set to '1' or higher.
* Copy the script to your mail system (e.g. to ```/usr/local/bin/```)
* Configure the script:
  * Set ```maillog``` to your postfix logfile
  * Set ```provider```to your service domain.
  * Optionally set ```contact``` to your contact mail address.
  * Optionally set ```out_rcpts``` to a list of mail addresses that should
    receive the summary regarding outgoing no-TLS mail. Alternatively, leave
    the option empty and the summary will be printed to *STDOUT*.
  * Optionally set ```sent_alert``` in order to warn postmasters about missing
    TLS support on their mail servers.
  * Optionally customize ```alert_subject``` and ```alert_body```.

* In order for the script to run automatically against the log file without
  producing duplicates, the easiest solution is to run it once after the log
  is rotated by ```logrotate```. This can be done by configuring a
  ```post-script``` in the corresponding *logrotate configure include*
  (e.g. ```/etc/logrotate.d/rsyslog```):
  ```
/var/log/mail.log
{
	[...]
	postrotate
		[...]
		/usr/local/bin/check-notls-mailservers.sh
	endscript
}
```

## Changelog

* 2017-01-22: initial version 0.5
  * release version 0.5
