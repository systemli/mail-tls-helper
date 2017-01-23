#!/bin/sh

# Script to check for outgoing mail that is not transport-encrypted
#
# * The script parses the Postfix mail log for outgoing mail that is not
#   transport-encrypted via TLS and gives a summary with some stats.
# * Optionally the script sends alert mails to the postmasters of receiving
#   mailserver without STARTTLS support.
#
# Note: this script requires Postfix SMTP client logging (smtp_tls_loglevel)
#       to be set to '1' or higher. See documentation of option
#       'smtp_tls_loglevel' in postconf(5) manpage for further information.
#
# Author: doobry@systemli.org
# Version: 0.5 (2017-01-22)
# License: public domain

# log file to run the script against
maillog="/var/log/mail.log.1"

# list of recipients of the summary output (leave emtpy for output to stdout)
#out_rcpts="john.doe@example.org"
out_rcpts=""

# contact detail configuration
provider="example.org"
contact="admin@$provider"

# alert message configuration
send_alerts="yes"
alert_subject="Please add TLS support to your mail system 'XRELAYX'"
alert_body="Hello postmaster for domain 'XMAILDOMAINX',

Your system 'XRELAYX' is among the last 1% of mail servers,
that still don't support TLS transport encryption for incoming messages.

The following mail domain is affected:

XMAILDOMAINX

In order to make the internet a safer place, we intend to disable
unencrypted mail delivery in the near future.

Please do your users a favour, join our effort and add STARTTLS support
to your mail setup.

See RFC 3207 for further information: https://tools.ietf.org/html/rfc3207

In case of any questions, don't hesitate to contact us at
$contact

Kind regards,
$provider sysadmins
"

notls_f="$(tempfile)"

# determine start and end date of the analyzed logs
date_first="$(sed -ne '1 s/^\([A-Za-z0-9: ]\{15\}\).*$/\1/gp' $maillog)"
date_last="$(sed -ne '$ s/^\([A-Za-z0-9: ]\{15\}\).*$/\1/gp' $maillog)"

# compile list of message IDs of successfully sent out messages
out_mids="$(sed -ne 's#^.*postfix/smtp\[\([0-9]\+\)\]: .*status=sent.*$#\1#gp' $maillog | sort | uniq | tr ' ' '\n')"
# compile list of message IDs that use TLS
tls_mids="$(sed -ne 's#^.*postfix/smtp\[\([0-9]\+\)\]: .*TLS connection established to.*$#\1#gp' $maillog | sort | uniq | tr ' ' '\n')"
out_mids_cnt="$(echo $out_mids | wc -w)"

for id in $out_mids; do
	if ! echo $tls_mids | grep -q $id; then
		# determine rcpt domain of no-TLS mail
		maildomain="$(sed -ne "s/^.*postfix\/smtp\[$id\]: .*to=<[^@]\+@\([^, ]\+\)>, .*status=sent.*$/\1/gp" $maillog | head -n1 | tr '[:upper:]' '[:lower:])"
		# determine receiving mailserver of no-TLS mail
		relay="$(sed -ne "s/^.*postfix\/smtp\[$id\]: .*relay=\([^, ]\+\), .*status=sent.*$/\1/gp" $maillog | head -n1 | tr '[:upper:]' '[:lower:])"
		# output all logs related to no-TLS mail for debugging purposes
		#grep "postfix\/smtp\[$id\]: " $maillog >>/tmp/check-notls-mailservers.log
		# detect TLS errors, don't send alert mails in this case
		unset tls_error; grep -q "postfix\/smtp\[$id\]: SSL_connect error" $maillog && tls_error="true"
		echo "mail to mailserver $relay (domain $maildomain)${tls_error+" [due to a TLS error]"}" >>"$notls_f"

		# send alerts to postmasters of mailservers without TLS support
		if [ "$send_alerts" = "yes" ] && [ -z "$tls_error" ]; then
			mailserver="${relay%\[0\.0\.0\.0\]:*}"
			if ! echo "$alerted_relays" | tr ' ' '\n' | grep -Fxq "$mailserver"; then
				alert_subject_x="$(echo $alert_subject | sed -e "s/XRELAYX/$mailserver/g")"
				echo "$alert_body" | sed -e "s/XMAILDOMAINX/$maildomain/g" -e "s/XRELAYX/$mailserver/g" | mailx -a "From: $contact" -s "$alert_subject_x" postmaster@$maildomain
				alerted_relays="${alerted_relays+$alerted_relays }$mailserver"
			fi
		fi
	fi
done

# count no-TLS messages
notls_mids_cnt="$(cat "$notls_f" | wc -l)"
# calculate percentage of no-TLS compared to all mails
notls_mids_pct="$(printf '%.2f\n' "$(echo "scale=2; $notls_mids_cnt*100/$out_mids_cnt" | bc)")"

# compile output if no-TLS mails were found
if [ -s "$notls_f" ]; then
	out_f="$(tempfile)"
	(
	  echo "Time range: $date_first - $date_last"
	  echo "Total number of total outgoing mails: $out_mids_cnt"
	  echo "Total number of no-TLS outgoing mails: $notls_mids_cnt"
	  echo "Percentage of no-TLS outgoing mails: $notls_mids_pct"
	  echo
	  echo "List of outgoing mails without TLS:"
	  cat "$notls_f" | sort | uniq -c
	  echo
	  if [ -n "$alerted_relays" ]; then
		echo "Sent alert mails to postmasters of the following systems:"
		for m in $alerted_relays; do
			echo "$m"
		done
	  fi
	) >"$out_f"

	# output or mail summary depending on config
	if [ -n "$out_rcpts" ]; then
		cat "$out_f" | mailx -E -s "mail-xeon: no-TLS outgoing mail" $out_rcpts
	else
		cat "$out_f"
	fi
	rm "$out_f"
fi

rm "$notls_f"
