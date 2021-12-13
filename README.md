# log4j_cop

Detect log4j payloads from a log file.

## Rules

Currently the following rules (and variants) are being accounted for:

* ${jndi:ldap://
* ${jndi:rmi://

## Algorithm

Each line is broken into characters and we check whether these characters match
one of our rulesets in the correct order, ignoring characters that do not match.

