# MSOLSpray Next-Generation

This projected started as a fork of
[MSOLSpray](https://github.com/MartinIngesen/MSOLSpray) and was later
renamed to
[MSOLSpray-ng](https://github.com/y0k4i-1337/MSOLSpray-ng) to avoid confusion
with the original project.

Since then, many features have been added and the project has been partially
refactored aiming OpSec and fine-tuning.

**The original project was a pure Python rewrite of [dafthack's MSOLSpray](https://github.com/dafthack/MSOLSpray/) which is written in PowerShell.**

MSOLSpray is a password spraying tool for Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.

**BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!**

## Why another spraying tool?
The main difference with this tool is that it is not only looking for valid passwords, but also the extremely verbose information Azure AD error codes give you. These error codes provide information relating to if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, if the account is disabled, if the password is expired and much more.

So this doubles as not only a password spraying tool but also a Microsoft Online recon tool that will provide account/domain enumeration. In limited testing it appears that on valid login to the Microsoft Online OAuth2 endpoint it isn't auto-triggering MFA texts/push notifications making this really useful for finding valid creds without alerting the target.

Lastly, this tool works well with
[FireProx](https://github.com/ustayready/fireprox) to rotate source IP
addresses on authentication requests. In testing this appeared to avoid getting
blocked by Azure Smart Lockout.

Since Amazon started to flag FireProx endpoints, the script now supports Tor
as well. You can use it with the `--tor` option. The script will then
automatically create a new Tor circuit after the specified interval.

## Tor

In order to proxy requests through Tor, you will have to configure your
`torrc` to open a control port and set a password. Instructions can be found
[here](https://wiki.archlinux.org/title/Tor#Open_Tor_ControlPort) and
[here](https://wiki.archlinux.org/title/Tor#Set_a_Tor_Control_password).

## Quick Start
### Requirements

The easiest way to install dependencies is with `poetry`. You can do this by running:
```
poetry install
```

Alternatively, you can use `pip`:
```
pip install -r requirements.txt
```

### MSOLSpray-ng

You will need a userlist file with target email-addresses one per line.
```
usage: msolspray-ng.py [-h] (-u USERNAME | -U FILE | -C FILE) [-p PASSWORD | -P FILE] [--sep SEP] [-o OUTFILE] [-x PROXY] [--url URL] [-f | --force-first] [--shuffle] [-a {0,1,2}] [--notify NOTIFY] [--notify-actions NOTIFY_ACTIONS] [--notify-each] [-s SLEEP] [--pause PAUSE]
                       [-j JITTER] [-l PERCENT] [-H HEADERS] [-A NAME] [--rua] [--timeout TIMEOUT] [--tor] [--tor-port SOCKS_PORT] [--tor-control-port CONTROL_PORT] [--tor-control-pw CONTROL_PW] [--tor-refresh-interval REFRESH_INTERVAL] [-v]

This script will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Single username
  -U FILE, --usernames FILE
                        File containing usernames in the format 'user@domain'.
  -C FILE, --creds FILE
                        File containing credentials in the format '<user><separator><password>'.
  -p PASSWORD, --password PASSWORD
                        Single password.
  -P FILE, --passwords FILE
                        File containing passwords, one per line.
  --sep SEP             Separator used when parsing credentials file in CSV format.
  -o OUTFILE, --out OUTFILE
                        A file to output valid results to (default: valid_creds.txt).
  -x PROXY, --proxy PROXY
                        Use proxy on requests (e.g. http://127.0.0.1:8080)
  --url URL             A comma-separated list of URL(s) to spray against (default: https://login.microsoft.com). Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
  -f, --force           Forces the spray to continue and not stop when multiple account lockouts are detected.
  --force-first         Like --force but only for first iteration. Use it with '-a 2' for optimization.
  --shuffle             Shuffle user list.
  -a {0,1,2}, --auto-remove {0,1,2}
                        Auto remove accounts from next iterations (0: valid credentials (default), 1: previous + nonexistent/disabled, 2: previous + locked).
  --notify NOTIFY       Slack webhook for sending notifications about results (default: None).
  --notify-actions NOTIFY_ACTIONS
                        Slack webhook for sending notifications about needed actions (default: same as --notify).
  --notify-each         If set in conjunction with --notify WEBHOOK, it will notify each valid creds besides final summary.
  -s SLEEP, --sleep SLEEP
                        Sleep this many seconds between tries (default: 0).
  --pause PAUSE         Pause (in minutes) between each iteration (default: 15).
  -j JITTER, --jitter JITTER
                        Maximum of additional delay given in percentage over base delay (default: 0).
  -l PERCENT, --max-lockout PERCENT
                        Maximum lockouts (in percent) to be observed before ask to abort execution. (default: 10).
  -H HEADERS, --header HEADERS
                        Extra header to include in the request (can be used multiple times).
  -A NAME, --user-agent NAME
                        Send User-Agent NAME to server (default: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36").
  --rua                 Send random User-Agent in each request.
  --timeout TIMEOUT     Timeout for requests (default: 4)
  --tor                 Use tor for requests.
  --tor-port SOCKS_PORT
                        Tor socks port to use (default: 9050).
  --tor-control-port CONTROL_PORT
                        Tor control port to use (default: 9051).
  --tor-control-pw CONTROL_PW
                        Password for Tor control port (default: None).
  --tor-refresh-interval REFRESH_INTERVAL
                        Interval (in number of login attempts) to refresh Tor circuit (default: 10).
  -v, --verbose         Prints usernames that could exist in case of invalid password.

EXAMPLE USAGE:
This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
    python3 msolspray-ng.py --userlist ./userlist.txt --password Winter2020

This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
    python3 msolspray-ng.py --userlist ./userlist.txt --password P@ssword --url https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox --out valid-users.txt

This command will create a new tor circuit every 5 login attempts and use it to spray from randomized IP addresses.
    python3 msolspray-ng.py --userlist ./userlist.txt --password P@ssword --tor --tor-control-pw H1d3M3 --tor-refresh-interval 5

TIPS:
[1] When using along with FireProx, pass option -H "X-My-X-Forwarded-For: 127.0.0.1" to spoof origin IP.
```
