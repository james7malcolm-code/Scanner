import argparse
from boofuzz import *
import os

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Target HTTP URL")
    args = parser.parse_args()

    url = args.url.strip("/")
    host = url.split("//")[1].split("/")[0]
    endpoint = "/" + "/".join(url.split("//")[1].split("/")[1:])

    os.makedirs("fuzz-output", exist_ok=True)

    # Boofuzz session
    session = Session(
        target=Target(
            connection=SocketConnection(
                host=host,
                port=80,
                proto="tcp"
            )
        ),
        crash_threshold_request=1,
        sleep_time=0.1,
    )

    s_initialize("HTTP Fuzz")

    if s_block_start("Request-Line"):
        s_string("GET", fuzzable=True)
        s_delim(" ", fuzzable=False)
        s_string(endpoint, fuzzable=True)
        s_delim(" ", fuzzable=False)
        s_string("HTTP/1.1", fuzzable=False)
        s_static("\r\n")
    s_block_end("Request-Line")

    s_string("Host", fuzzable=False)
    s_delim(": ")
    s_string(host, fuzzable=True)
    s_static("\r\n")

    s_string("User-Agent", fuzzable=False)
    s_delim(": ")
    s_string("BoofuzzFuzzer", fuzzable=True)
    s_static("\r\n")

    s_static("\r\n")

    session.connect(s_get("HTTP Fuzz"))
    session.fuzz()

    print("Fuzzing finished. Logs stored in fuzz-output/")

if __name__ == "__main__":
    main()
