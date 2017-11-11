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
import datetime, sqlite3
import getopt, sys
from collections import defaultdict
from subprocess import call
from subprocess import Popen, PIPE
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
import pprint

name = "mail-tls-helper.py"
version = "0.8.1"

alertTTL = 30

global op
op = {}

# Structure for pidDict
def relayFactory():
    return {
        'domains': set(),
        'sentCount': 0,
        'sentCountTLS': 0,
        'tlsCount': 0,
        'isTLS': False,
    }

def pidFactory():
    return defaultdict(relayFactory)

# Parse options
def options(args):
    op['printHelp'] = False
    op['printVersion'] = False

    try:
        opts, args = getopt.getopt(args, 'ad:f:hl:m:Op:Pr:s:SVw:',
            ['alerts', 'domain=', 'debug', 'from=', 'help',
             'mail-log=', 'mode=', 'no-postmap', 'postfix-map-file=',
             'no-postfix-map', 'rcpts=', 'sqlite-db=', 'no-summary',
             'version', 'whitelist='])
    except getopt.error as exc:
        print("%s: %s, try -h for a list of all the options" % (name, str(exc)), file=sys.stderr)
        sys.exit(255)

    for opt, arg in opts:
        if opt in ['-h', '--help']:
            op['printHelp'] = True
            break
        elif opt in ['-V', '--version']:
            op['printVersion'] = True
            break
        elif opt in ['-m', '--mode']:
            if (arg == 'postfix'):
                op['mode'] = arg
            else:
                print("%s: unknon mode %s, try -h for a list of all the options" % (name, arg), file=sys.stderr)
                sys.exit(255)
        elif opt in ['--debug']:
            op['debug'] = True
        elif opt in ['-l', '--mail-log']:
            op['mailLog'] = arg
        elif opt in ['-w', '--whitelist']:
            op['whitelist'] = arg
        elif opt in ['-P', '--no-postfix-map']:
            op['postfixMap'] = False
        elif opt in ['-p', '--postfix-map-file']:
            op['postfixMapFile'] = arg
        elif opt in ['-O', '--no-postmap']:
            op['postMap'] = False
        elif opt in ['-s', '--sqlite-db']:
            op['sqliteDB'] = arg
        elif opt in ['-a', '--alerts']:
            op['alerts'] = True
        elif opt in ['-S', '--no-summary']:
            op['summary'] = False
        elif opt in ['-d', '--domain']:
            op['domain'] = arg
        elif opt in ['-f', '--from']:
            op['from'] = arg
        elif opt in ['-r', '--rcpts']:
            op['rcpts'] = arg.split(',')

    # Set options to defaults if not set yet
    op['debug']      = op.get('debug', False)
    op['mode']       = op.get('mode', "postfix")
    op['mailLog']    = op.get('mailLog', "/var/log/mail.log.1")
    op['whitelist']  = op.get('whitelist', False)
    op['postfixMap'] = op.get('postfixMap', True)
    op['postfixMapFile'] = op.get('postfixMapFile', "/etc/postfix/tls_policy")
    op['postMap']    = op.get('postMap', True)
    op['sqliteDB']   = op.get('sqliteDB', "/var/lib/mail-tls-helper/notls.sqlite")
    op['alerts']     = op.get('alerts', False)
    op['summary']    = op.get('summary', True)
    op['domain']     = op.get('domain', "example.org")
    op['from']       = op.get('from', "admin@%s" % op['domain'])
    op['rcpts']      = op.get('rcpts', [ "admin@%s" % op['domain'] ])
    op['summSubj']  = op.get('sumSubj', "[%s] mail-tls-helper summary" % (os.uname()[1]))
    op['summBody']  = op.get('sumSubj', "Summary mail by mail-tls-helper on %s" % (os.uname()[1]))
    op['alertSubj'] = op.get('alertSubj', "Please add TLS support to the mailservers for 'XDOMAINX'")
    op['alertBody'] = op.get('alertBody', """Hello postmaster for mail domain 'XDOMAINX',

Your mail server for 'XDOMAINX' is among the last mail servers,
that still don't support TLS transport encryption for incoming messages.


In order to make the internet a safer place, we intend to disable
unencrypted mail delivery in the near future.

Please do your users a favour, join our effort and add STARTTLS support
to your mail setup.

See RFC 3207 for further information: https://tools.ietf.org/html/rfc3207

In case of any questions, don't hesitate to contact us at
%s

Kind regards,
%s sysadmins
""" % (op['from'], op['domain']))

    if op['printHelp']:
        print("usage: %s [options]" % name, file=sys.stderr)
        print("""
Postfix helper script that does the following:
 * make TLS mandatory for outgoing mail wherever possible and
 * optionally alert postmasters of mailservers that don't support STARTTLS

%s options:
  -h, --help                   display this help message
  -V, --version                display version number
      --debug                  run in debugging mode, don't do anything
  -m, --mode=[postfix]         set mode (default: %s, no others supported yet)
  -l, --mail-log=file          set mail log file (default: %s)
  -w, --whitelist=file         file containing relay whitelist
  -p, --postfix-map-file=file  set Postfix TLS policy map file (default: %s)
  -s, --sqlite-db=file         set SQLite DB file (default: %s)
  -a, --alerts                 send out alert mails
  -S, --no-summary             don't send out summary mail
  -P, --no-postfix-map         don't update the Postfix TLS policy map file
  -O, --no-postmap             don't postmap(1) the Postfix TLS policy map file
  -d, --domain=name            set organization domain (default: %s)
  -f, --from=address           set sender address (default: %s)
  -r, --rcpts=addressses       set summary mail rcpt addresses (default: %s)
""" % (name, op['mode'], op['mailLog'], op['postfixMapFile'], op['sqliteDB'], op['domain'], op['from'], ','.join(op['rcpts'])), file=sys.stderr)
        sys.exit(0)
    elif op['printVersion']:
        print("%s %s" % (name, version), file=sys.stderr)
        sys.exit(0)


def print_dbg(msg):
    if op['debug']:
        print("DEBUG: %s" % msg)


def print_dbg_pid(pid, dictx):
    print_dbg("PID: %s" % pid)
    for relay in dictx:
        if dictx[relay]['tlsCount'] != dictx[relay]['sentCount']:
            print_dbg_relay(relay, dictx[relay])

def print_dbg_relay(relay, dictx):
    print_dbg(" relay: %s" % relay)
    print_dbg("  domains: %s"   % dictx['domains'])
    print_dbg("  tlsCount: %s"  % dictx['tlsCount'])
    print_dbg("  sentCount: %s" % dictx['sentCount'])


# Postfix TLS policy table functions
def postfixTlsPolicyUpdate(domainsTLS, postfixMapFile, postMap):
    if os.path.isfile(postfixMapFile):
        policyFileLines = [line.split()[0] for line in open(postfixMapFile, 'r')]
        policyFile = open(postfixMapFile, 'a')
        for domain in domainsTLS:
            if domain not in policyFileLines:
                print_dbg("Add domain '%s' to Postfix TLS policy map" % domain)
                if not op['debug']: policyFile.write("%s encrypt\n" % domain)
        policyFile.close()

    if postMap and not op['debug']:
        call(["postmap", postfixMapFile])


def notlsProcess(domainsTLS, domainsNoTLS, sqliteDB):
    # 
    domainDBNoTLS = {}
    if os.path.isfile(sqliteDB):
        conn = sqlite3.connect(sqliteDB)
        c = conn.cursor()
        c.execute('''SELECT * FROM notlsDomains;''')
        rows = c.fetchall()
        conn.close()
        for item in rows:
            domainDBNoTLS[item[0]] = {
                'alertCount': item[1],
                'alertDate': item[2],
            }

    op['summBody'] += "\nList of domains with no-TLS connections:"
    conn = sqlite3.connect(sqliteDB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS notlsDomains (domain text, alertCount integer, alertDate date);''')
    for domain in domainsTLS:
        if domain in domainDBNoTLS:
            print_dbg("Delete domain %s from sqlite DB" % domain)
            if not op['debug']: c.execute('''DELETE FROM notlsDomains WHERE domain = ?;''', [domain])
    for domain in domainsNoTLS:
        if domain in domainsTLS:
            # ignore individual no-TLS connections when other connections
            # for the same domain were encrypted. TLS will be mandatory
            # in the future anyway for this domain.
            continue
        op['summBody'] += "\n * %s" % (domain)
        if domain in domainDBNoTLS:
            # send alerts every <alertTTL> days
            slist = domainDBNoTLS[domain]['alertDate'].split('-')
            if not datetime.date(int(slist[0]),int(slist[1]),int(slist[2])) < datetime.date.today()+datetime.timedelta(-alertTTL):
                continue
            else:
                print_dbg("Update domain %s in sqlite DB" % domain)
                if not op['debug']: c.execute('''UPDATE notlsDomains SET alertCount=?, alertDate=? WHERE domain = ?;''', (domainDBNoTLS[domain]['alertCount']+1, datetime.date.today(), domain))
        else:
            print_dbg("Insert domain %s into sqlite DB" % domain)
            if not op['debug']: c.execute('''INSERT INTO notlsDomains (domain, alertCount, alertDate) VALUES (?,?,?);''', (domain, 1, datetime.date.today()))
        if op['alerts']:
            op['summBody'] += " [sent alert mail]"
            sendMail(op['from'], ['postmaster@'+domain],
                     op['alertSubj'].replace('XDOMAINX', domain),
                     op['alertBody'].replace('XDOMAINX', domain))
    op['summBody'] += "\n\n"
    conn.commit()
    conn.close()


def readWhitelist(wlfile):
    whitelist = []
    if wlfile:
        with open(wlfile, 'r') as f:
            whitelist = f.readlines()
    whitelist = [x.strip() for x in whitelist]
    # always add localhost to whitelist
    whitelist.extend(['localhost', '127.0.0.1', '::1'])
    return whitelist


def sendMail(sender, to, subject, text, server="/usr/sbin/sendmail"):
    assert type(to)==list
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = COMMASPACE.join(to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(text))
    if op['debug']:
        print_dbg("Mail: %s" % msg.as_string())
    else:
        if server == "/usr/sbin/sendmail":
            p = Popen([server, "-t", "-oi", "-f", sender], stdin=PIPE)
            p.communicate(msg.as_string())
        else:
            smtp = smtplib.SMTP(server)
            smtp.sendmail(sender, to, msg.as_string())
            smtp.close()


def postfixParseLog(logfile, whitelist):
    # Postfix regexes
    regex_smtp = re.compile(r" postfix/smtp\[(?P<pid>[0-9]+)\]: (?P<msgid>[0-9A-F]+): to=<[^@]+@(?P<domain>[^, ]+)>, .*relay=(?P<relay>[\w\-\.]+)\[[0-9A-Fa-f\.:]+\]:[0-9]{1,5}, .*status=(?P<status>[a-z]+)")
    regex_tls  = re.compile(r" postfix/smtp\[(?P<pid>[0-9]+)\]: .*TLS connection established to (?P<relay>[\w\-\.]+)\[[0-9A-Fa-f\.:]+\]:[0-9]{1,5}")

    # Read SMTP client connections from Postfix logfile into pidDict
    # * SMTP client connection logs don't contain TLS evidence. Thus
    #   TLS connections logs have to be parsed alongside.
    # * Beware:
    #   * Postfix sends several mails - even to different relays - under one
    #     PID, each one with a separate msgID.
    #   * Several connections may exist per msgID (e.g. if first attempt to
    #     send fails).
    #   * One TLS connection may be used to send several mails to one relay.
    # * What we do:
    #   * Pair PID and relay, write stats for that pair into pidDict[relay]

    pidDict = defaultdict(pidFactory)
    lineCount = sentCount = tlsCount = 0
    with open(logfile, "r") as f:
        for line in f:
            lineCount += 1
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
    relayDict = defaultdict(relayFactory)
    for pid in pidDict:
        #print_dbg_pid(pid, pidDict[pid])
        for relay in pidDict[pid]:
            for x in pidDict[pid][relay]['domains']:
                relayDict[relay]['domains'].add(x)
            relayDict[relay]['sentCount'] += pidDict[pid][relay]['sentCount']
            
            if (pidDict[pid][relay]['tlsCount'] > 0 and
                pidDict[pid][relay]['sentCount'] > 0):
                # At least one encrypted connection and one delivered message
                relayDict[relay]['sentCountTLS'] += pidDict[pid][relay]['sentCount']
                relayDict[relay]['isTLS'] = True
            elif (pidDict[pid][relay]['tlsCount'] > 0):
                # No message got delivered, still encrypted connection: ignore
                relayDict[relay]['isTLS'] = True
            #else:
                # Only unencrypted connections

    return relayDict


# Untested Exim4 regexes:
regex_exim4_smtp = re.compile(r"(?P<msgid>[\w\-]{14}) [=-]> .*T=remote_smtp .*H=(?P<relay>[\w\-\.]+) .*(X=(?P<tlsver>[A-Z0-9\.]+):[\w\-\.:_]+)? .*C=\"(?P<response>[^\"]+)\"")

# Main function
if __name__ == '__main__':
    # process commandline options
    options(sys.argv[1:])

    # read in the whitelist
    whitelist = readWhitelist(op['whitelist'])

    # fill the relayDict by parsing mail logs
    if op['mode'] == 'postfix':
        relayDict = postfixParseLog(op['mailLog'], whitelist)

    # fill domainsTLS and domainsNoTLS from relayDict
    domainsTLS   = set()
    domainsNoTLS = set()
    sentCountTotal = sentCountTLS = 0
    for relay in relayDict:
        sentCountTotal += relayDict[relay]['sentCount']
        sentCountTLS   += relayDict[relay]['sentCountTLS']
        if relayDict[relay]['isTLS']:
            for domain in relayDict[relay]['domains']:
                domainsTLS.add(domain)
        else:
            for domain in relayDict[relay]['domains']:
                domainsNoTLS.add(domain)

    # print a summary
    op['summBody'] += "\n\nTotal count of sent messages:             %s\n" % sentCountTotal
    op['summBody'] += "Total count of messages sent without TLS: %s\n" % (sentCountTotal-sentCountTLS)
    op['summBody'] += "Percentage of messages sent without TLS:  %.2f%%\n" % ((sentCountTotal-sentCountTLS)/float(sentCountTotal)*100)

    # update the SQLite database with noTLS domains
    if len(domainsNoTLS) > 0:
        notlsProcess(domainsTLS, domainsNoTLS, op['sqliteDB'])

    # update the TLS policy map
    if (op['mode'] == 'postfix' and op['postfixMap'] and len(domainsTLS) > 0):
        postfixTlsPolicyUpdate(domainsTLS, op['postfixMapFile'], op['postMap'])

    if (len(domainsNoTLS) > 0 and op['summary']):
        sendMail(op['from'],op['rcpts'],op['summSubj'],op['summBody'])
