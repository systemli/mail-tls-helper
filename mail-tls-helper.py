#!/usr/bin/python

# Postfix helper script that does the following:
#  * make TLS mandatory for outgoing mail wherever possible and
#  * alert postmasters of mailservers that don't support STARTTLS
#
# Author: doobry@systemli.org
# Version: 0.8.1 [2017-11-11]
# License: GPL-3
#
# TODO:
# * implement blacklist of domains/relays not to notify when no-tls (?)
# * writer log parser and hash map creator for exim4
# * make more things configurable via commandline:
#   * interval between mails to postmasters

from __future__ import print_function
import os
import re
import datetime
import sqlite3
import argparse
from collections import defaultdict
from subprocess import call
from subprocess import Popen, PIPE
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

name = "mail-tls-helper.py"
version = "0.8.1"

ALERT_TTL = datetime.timedelta(days=30)

# date format used for storing timestamps in database
DB_DATE_FORMAT = '%Y-%m-%d'

LOCALHOST_WHITELIST = {'localhost', '127.0.0.1', '::1'}
# sadly we currently handle this as a global variable (controlled via "--debug")
DEBUG_MODE_ENABLED = False


# Structure for pidDict
def relayFactory():
    return {
        'domains': set(),
        'sentCount': 0,
        'sentCountTLS': 0,
        'tlsCount': 0,
        'isTLS': False,
        'tls_required_but_not_offered': False,
    }


def pidFactory():
    return defaultdict(relayFactory)


# Parse options
def parse_args():
    description = '''Postfix helper script that does the following:
 * make TLS mandatory for outgoing mail wherever possible and
 * optionally alert postmasters of mailservers that do not support STARTTLS'''
    parser = argparse.ArgumentParser(prog=name, description=description,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(version))
    parser.add_argument('--debug', action='store_true',
                        help="run in debugging mode, don't do anything")
    parser.add_argument('-m', '--mode', choices=('postfix', ), default='postfix',
                        help='mode (currently only "postfix")')
    try:
        utf8_filetype = argparse.FileType('r', encoding='utf8')
    except TypeError:
        # fallback for Python2
        utf8_filetype = argparse.FileType('r')
    parser.add_argument('-l', '--mail-log', type=utf8_filetype, dest='mail_logfile',
                        default='/var/log/mail.log.1', help='mail log file')
    parser.add_argument('-w', '--whitelist', type=utf8_filetype, dest='whitelist',
                        help='optional file containing relay whitelist')
    parser.add_argument('-p', '--postfix-map-file', dest='postfix_map_file', type=str,
                        default='/etc/postfix/tls_policy', help='Postfix TLS policy map file')
    parser.add_argument('-s', '--sqlite-db', dest='sqlite_db',
                        default='/var/lib/mail-tls-helper/notls.sqlite',
                        help='SQLite DB file for internal state storage (created if missing)')
    parser.add_argument('-a', '--alerts', dest='send_alerts', action='store_true',
                        help=('send out alert mails to the "postmaster" addresses of external '
                              'mail domains lacking TLS support'))
    parser.add_argument('-S', '--no-summary', dest='send_summary', action='store_false',
                        help='do not send out summary mail')
    parser.add_argument('-P', '--no-postfix-map', dest='use_postfix_map', action='store_false',
                        help='do not update the Postfix TLS policy map file')
    parser.add_argument('-O', '--no-postmap', dest='run_postmap', action='store_false',
                        help='do not "postmap(1)" the Postfix TLS policy map file')
    parser.add_argument('-d', '--domain', type=str, default='example.org',
                        help=('the organization domain is used for defaults of "-r" and "-f" and '
                              'within the alert mail text body'))
    parser.add_argument('-f', '--from', type=str, dest='from_address',
                        help='sender/from mail address (default: "admin@DOMAIN", see "--domain")')
    parser.add_argument('-r', '--rcpts', action='append', dest='recipients', help=(
        'summary mail recipient address (default: "admin@DOMAIN", see "--domain")'))

    args = parser.parse_args()
    # set some non-trivial defaults
    if not args.from_address:
        args.from_address = 'admin@{}'.format(args.domain)
    if not args.recipients:
        args.recipients = ['admin@{}'.format(args.domain)]
    # add details that are currently not configurable
    # This is a slight abuse of the arguments namespace, but this should be acceptable.
    args.summary_subject = '[{}] mail-tls-helper summary'.format(os.uname()[1])
    args.summary_start = 'Summary mail by mail-tls-helper on {}'.format(os.uname()[1])
    args.alert_subject = "Please add TLS support to the mailservers for 'XDOMAINX'"
    args.alert_body = """Hello postmaster for mail domain 'XDOMAINX',

Your mail server for 'XDOMAINX' is among the last mail servers,
that still do not support TLS transport encryption for incoming messages.


In order to make the internet a safer place, we intend to disable
unencrypted mail delivery in the near future.

Please do your users a favour, join our effort and add STARTTLS support
to your mail setup.

See RFC 3207 for further information: https://tools.ietf.org/html/rfc3207

In case of any questions, don't hesitate to contact us at
{from_address}

Kind regards,
{domain} sysadmins""".format(from_address=args.from_address, domain=args.domain)
    return args


def print_dbg(msg):
    if DEBUG_MODE_ENABLED:
        print("DEBUG: %s" % msg)


def print_dbg_pid(pid, dictx):
    print_dbg("PID: %s" % pid)
    for relay in dictx:
        if dictx[relay]['tlsCount'] != dictx[relay]['sentCount']:
            print_dbg_relay(relay, dictx[relay])


def print_dbg_relay(relay, dictx):
    print_dbg(" relay: %s" % relay)
    print_dbg("  domains: %s" % dictx['domains'])
    print_dbg("  tlsCount: %s" % dictx['tlsCount'])
    print_dbg("  sentCount: %s" % dictx['sentCount'])


# Postfix TLS policy table functions
def postfixTlsPolicyUpdate(domainsTLS, postfixMapFile, postMap):
    if os.path.isfile(postfixMapFile):
        existing_policy_domains = set()
        with open(postfixMapFile, 'r') as in_file:
            for line in in_file:
                if line.strip():
                    domain = line.strip().split()[0]
                    existing_policy_domains.add(domain)
        missing_policy_domains = domainsTLS.difference(existing_policy_domains)
        if missing_policy_domains:
            with open(postfixMapFile, 'a') as policyFile:
                for domain in missing_policy_domains:
                    print_dbg("Add domain '%s' to Postfix TLS policy map" % domain)
                    if not DEBUG_MODE_ENABLED:
                        policyFile.write("%s encrypt\n" % domain)

    if postMap and not DEBUG_MODE_ENABLED:
        call(["postmap", postfixMapFile])


def notlsProcess(domainsTLS, domainsNoTLS, sqliteDB):
    """ update entries of non-TLS domains in the sqlite database and send alerts if requested

    The set of domains, whose postmasters are eligible for being notified, is returned.
    """
    if os.path.isfile(sqliteDB):
        conn = sqlite3.connect(sqliteDB)
        c = conn.cursor()
        c.execute('''SELECT * FROM notlsDomains;''')
        rows = c.fetchall()
        conn.close()
        domainDBNoTLS = {domain: {'alertCount': alert_count, 'alertDate': alert_date}
                         for domain, alert_count, alert_date in rows}
    else:
        domainDBNoTLS = {}

    # The set of mail domains whose postmasters could be notified now due to the missing TLS
    # connection. Only domains that were not alerted since <ALERT_TTL> are added to this set.
    alert_candidate_domains = set()
    conn = sqlite3.connect(sqliteDB)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS notlsDomains '
              '(domain text, alertCount integer, alertDate date);')
    for domain in domainsTLS:
        if domain in domainDBNoTLS:
            print_dbg("Delete domain %s from sqlite DB" % domain)
            if not DEBUG_MODE_ENABLED:
                c.execute('''DELETE FROM notlsDomains WHERE domain = ?;''', [domain])
    now = datetime.datetime.now()
    now_string = now.strftime(DB_DATE_FORMAT)
    for domain in domainsNoTLS:
        if domain in domainDBNoTLS:
            # We have seen this domain before.
            # Determine if another alert should be sent (every <ALERT_TTLD> days).
            try:
                last_alert_date = datetime.datetime.strptime(domainDBNoTLS[domain]['alertDate'],
                                                             DB_DATE_FORMAT)
            except ValueError:
                # handle parse error gracefully
                print_dbg("Failed to parse date string from database: {}"
                          .format(domainDBNoTLS[domain]['alertDate']))
                last_alert_date = None
            if last_alert_date + ALERT_TTL > now:
                # The latest alert is older than ALERT_TTL.
                alert_candidate_domains.add(domain)
                print_dbg("Update domain %s in sqlite DB" % domain)
                if not DEBUG_MODE_ENABLED:
                    c.execute(
                        'UPDATE notlsDomains SET alertCount=?, alertDate=? WHERE domain = ?;',
                        (domainDBNoTLS[domain]['alertCount'] + 1, now_string, domain))
        else:
            alert_candidate_domains.add(domain)
            print_dbg("Insert domain %s into sqlite DB" % domain)
            if not DEBUG_MODE_ENABLED:
                c.execute('INSERT INTO notlsDomains (domain, alertCount, alertDate) '
                          'VALUES (?,?,?);', (domain, 1, now_string))
    conn.commit()
    conn.close()
    return alert_candidate_domains


def readWhitelist(wlfile):
    if wlfile:
        parsed_whitelist = set(item.strip() for item in wlfile.readlines())
        wlfile.close()
    else:
        parsed_whitelist = set()
    return parsed_whitelist


def sendMail(sender, to, subject, text, server="/usr/sbin/sendmail"):
    assert type(to) == list
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = COMMASPACE.join(to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(text))
    if DEBUG_MODE_ENABLED:
        print_dbg("Mail: %s" % msg.as_string())
    else:
        if server == "/usr/sbin/sendmail":
            p = Popen([server, "-t", "-oi", "-f", sender], stdin=PIPE)
            try:
                # Python3
                msg_data = msg.as_bytes()
            except AttributeError:
                # Python2
                msg_data = msg.as_string()
            p.communicate(msg_data)
        else:
            smtp = smtplib.SMTP(server)
            smtp.sendmail(sender, to, msg.as_string())
            smtp.close()


def postfixParseLog(logfile, whitelist):
    # Postfix regexes
    regex_smtp = re.compile(r" postfix/smtp\[(?P<pid>[0-9]+)\]: "
                            r"(?P<msgid>[0-9A-F]+): to=<[^@]+@(?P<domain>[^, ]+)>, .*"
                            r"relay=(?P<relay>[\w\-\.]+)\[[0-9A-Fa-f\.:]+\]:[0-9]{1,5}, .*"
                            r"status=(?P<status>[a-z]+)")
    regex_tls = re.compile(r" postfix/smtp\[(?P<pid>[0-9]+)\]: .*TLS connection established to "
                           r"(?P<relay>[\w\-\.]+)\[[0-9A-Fa-f\.:]+\]:[0-9]{1,5}")
    regex_tls_missing = re.compile(r" postfix/smtp\[(?P<pid>[0-9]+)\]: (?P<msgid>[0-9A-F]+): "
                                   r"TLS is required, but was not offered by host "
                                   r"(?P<relay>[\w\-\.]+)\[[0-9A-Fa-f\.:]+\]")

    # Read SMTP client connections from Postfix logfile into pidDict
    # * SMTP client connection logs don't contain TLS evidence. Thus TLS connections logs have to
    #   be parsed alongside.
    # * Beware:
    #   * Postfix sends several mails - even to different relays - under one PID, each one with a
    #     separate msgID.
    #   * Several connections may exist per msgID (e.g. if first attempt to send fails).
    #   * One TLS connection may be used to send several mails to one relay.
    # * What we do:
    #   * Pair PID and relay, write stats for that pair into pidDict[relay]

    relayDict = defaultdict(relayFactory)
    pidDict = defaultdict(pidFactory)
    lineCount = sentCount = tlsCount = 0
    for line in logfile:
        lineCount += 1
        m = regex_tls_missing.search(line)
        if m:
            relay = m.group('relay').lower()
            pidDict[m.group('pid')][relay]['tls_required_but_not_offered'] = True
            continue
        # search for SMTP client connections
        m = regex_smtp.search(line)
        if m:
            relay = m.group('relay').lower()
            if relay in whitelist:
                print_dbg("Skipping relay from whitelist: %s (smtp)" % relay)
                continue
            domain = m.group('domain').lower()
            pidDict[m.group('pid')][relay]['domains'].add(domain)
            if m.group('status') == 'sent':
                pidDict[m.group('pid')][relay]['sentCount'] += 1
                sentCount += 1
            continue
        # search for TLS connections
        m = regex_tls.search(line)
        if m:
            relay = m.group('relay').lower()
            if relay in whitelist:
                print_dbg("Skipping relay from whitelist: %s (tls)" % relay)
                continue
            tlsCount += 1
            pidDict[m.group('pid')][relay]['tlsCount'] += 1

    print_dbg("postfixParseLog: Processed lines: %s" % lineCount)
    print_dbg("postfixParseLog: Delivered messages: %s" % sentCount)
    print_dbg("postfixParseLog: TLS connections: %s" % tlsCount)

    # Transform pidDict into relayDict
    for pid in pidDict:
        # optional PID output: print_dbg_pid(pid, pidDict[pid])
        for relay in pidDict[pid]:
            for x in pidDict[pid][relay]['domains']:
                relayDict[relay]['domains'].add(x)
            relayDict[relay]['sentCount'] += pidDict[pid][relay]['sentCount']
            # "tls_required_but_not_offered" is set, if such a message was encountered for at least
            # one relay of the domain.
            if pidDict[pid][relay]['tls_required_but_not_offered']:
                relayDict[relay]['tls_required_but_not_offered'] = True
            if (pidDict[pid][relay]['tlsCount'] > 0) and (pidDict[pid][relay]['sentCount'] > 0):
                # At least one encrypted connection and one delivered message
                relayDict[relay]['sentCountTLS'] += pidDict[pid][relay]['sentCount']
                relayDict[relay]['isTLS'] = True
            elif (pidDict[pid][relay]['tlsCount'] > 0):
                # No message got delivered, still encrypted connection: ignore
                relayDict[relay]['isTLS'] = True
            else:
                # Only unencrypted connections
                pass

    return relayDict


# Untested Exim4 regexes:
regex_exim4_smtp = re.compile(
    r'(?P<msgid>[\w\-]{14}) [=-]> .*T=remote_smtp .*H=(?P<relay>[\w\-\.]+) .*'
    r'(X=(?P<tlsver>[A-Z0-9\.]+):[\w\-\.:_]+)? .*C="(?P<response>[^"]+)"')


# Main function
if __name__ == '__main__':
    # process commandline options
    # TODO: remove the ugly implicit exposure of this variable to the other function
    args = parse_args()
    DEBUG_MODE_ENABLED = args.debug

    # read in the whitelist
    whitelist = readWhitelist(args.whitelist).union(LOCALHOST_WHITELIST)

    # fill the relayDict by parsing mail logs
    if args.mode == 'postfix':
        relayDict = postfixParseLog(args.mail_logfile, whitelist)

    # fill domainsTLS and domainsNoTLS from relayDict
    domainsTLS = set()
    domainsNoTLS = set()
    relaysMissingTLS = set()
    sentCountTotal = sentCountTLS = 0
    for relay in relayDict:
        sentCountTotal += relayDict[relay]['sentCount']
        sentCountTLS += relayDict[relay]['sentCountTLS']
        if relayDict[relay]['isTLS']:
            for domain in relayDict[relay]['domains']:
                domainsTLS.add(domain)
        else:
            for domain in relayDict[relay]['domains']:
                domainsNoTLS.add(domain)
        if relayDict[relay]['tls_required_but_not_offered']:
            relaysMissingTLS.add(relay)
    # Ignore individual no-TLS connections if other connections for the same domain were encrypted.
    # TLS will be mandatory in the future anyway for this domain.
    domainsNoTLS.difference_update(domainsTLS)

    # print a summary
    summary_lines = []
    summary_lines.append("Total count of sent messages:             %s" % sentCountTotal)
    summary_lines.append("Total count of messages sent without TLS: %s"
                         % (sentCountTotal - sentCountTLS))
    if sentCountTotal > 0:
        summary_lines.append("Percentage of messages sent without TLS:  %.2f%%"
                             % ((sentCountTotal - sentCountTLS) / float(sentCountTotal) * 102))
    if relaysMissingTLS:
        summary_lines.append("")
        summary_lines.append("Some domains are configured to require TLS, "
                             "but their relays did not offer StartTLS:")
        for relay in sorted(relaysMissingTLS):
            if relayDict[relay]['domains']:
                summary_lines.append(" * MX {}:".format(relay))
                for domain in relayDict[relay]['domains']:
                    summary_lines.append("   * %s" % domain)
            else:
                # Sadly the "TLS required" message only includes the relay name (no mail domains).
                summary_lines.append(" * MX {} (no related mail domains known)".format(relay))

    # update the SQLite database with noTLS domains
    if len(domainsNoTLS) > 0:
        alertable_domains = notlsProcess(domainsTLS, domainsNoTLS, args.sqlite_db)
        summary_lines.append("")
        summary_lines.append("List of domains with no-TLS connections:")
        for domain in sorted(domainsNoTLS):
            summary_lines.append(" * %s" % (domain))
            if args.send_alerts and (domain in alertable_domains):
                recipient = 'postmaster@{}'.format(domain)
                summary_lines.append(" [sent alert mail: {}]".format(recipient))
                sendMail(args.from_address, [recipient],
                         args.alert_subject.replace('XDOMAINX', domain),
                         args.alert_body.replace('XDOMAINX', domain))
        summary_lines.append("")
        summary_lines.append("")

    # update the TLS policy map
    if (args.mode == 'postfix') and args.use_postfix_map and (len(domainsTLS) > 0):
        postfixTlsPolicyUpdate(domainsTLS, args.postfix_map_file, args.run_postmap)

    if (len(domainsNoTLS) > 0) and args.send_summary:
        summary_text = args.summary_start + "\n\n" + "\n".join(summary_lines)
        sendMail(args.from_address, args.recipients, args.summary_subject, summary_text)
