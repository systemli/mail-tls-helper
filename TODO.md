# ToDo list for mail-tls-helper

* implement blacklist of domains/relays not to notify when no-tls (?)
* writer log parser and hash map creator for exim4
* care about the actual certificates and possible DANE/MTA-STS policies
  * idea: after a configurable time of valiated certs/DANE records/...,
    turn `smtp_tls_security_level` from `encrypt` into `verify` or
    `dane-only` in the TLS transport map.
    * a clear idea how to deal with cert rotation etc.
* make more things configurable via commandline:
  * interval between mails to postmasters
