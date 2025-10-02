from msolspray.utils import print_error, print_success
import requests


def test_tor(socks_port: int):
    # test Tor socks port
    test_url = "https://check.torproject.org"
    proxies = {
        "http": f"socks5h://127.0.0.1:{socks_port}",
        "https": f"socks5h://127.0.0.1:{socks_port}",
    }

    response = requests.get(test_url, proxies=proxies, timeout=10, verify=False)
    text = response.text
    if response.status_code != 200:
        raise Exception(
            f"Tor test request failed with status code {response.status_code}"
        )
    else:
        if "Sorry. You are not using Tor." in text:
            print_error("Tor is not working correctly.")
        elif "Congratulations. This browser is configured to use Tor." in text:
            print_success("Tor is working correctly.")
        else:
            raise Exception("Unexpected response from Tor check page: " + text)


def generate_tor_circuits_urls(socks_port: int, tor_pool: int) -> list:
    """Generate a list of Tor socks URLs to create new circuits.

    Args:
        socks_port (int): Tor socks port
        tor_pool (int): Number of Tor circuits to create

    Returns:
        List[str]: List of Tor socks proxy URLs
    """
    return [f"socks5h://tor{i}:password@127.0.0.1:{socks_port}" for i in range(tor_pool)]


def test_circuits(socks_port: int, tor_pool: int) -> None:
    """Test if Tor circuits are working correctly.

    Args:
        socks_port (int): Tor socks port
        tor_pool (int): Number of Tor circuits to create

    Returns:
        None
    """
    test_url = "https://api.ipify.org"
    # get max number of digits in count
    digits = len(str(tor_pool))
    proxies_list = generate_tor_circuits_urls(socks_port, tor_pool)

    for i, proxy in enumerate(proxies_list):
        proxies = {
            "http": proxy,
            "https": proxy,
        }
        try:
            response = requests.get(test_url, proxies=proxies, timeout=10, verify=False)
            if response.status_code == 200:
                print_success(f"Tor circuit {i+1:>{digits}}: {response.text.strip()}")
            else:
                print_error(
                    f"Tor circuit {i+1:>{digits}}: failed with status code {response.status_code}"
                )
        except Exception as e:
            print_error(f"Tor circuit {i+1:>{digits}}: failed with error: {e}")
