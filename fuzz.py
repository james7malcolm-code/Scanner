import argparse
from boofuzz import *
import os
from urllib.parse import urlparse
from boofuzz import FuzzLoggerText, TCPSocketConnection  # explicit imports

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Target HTTP URL")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    host = parsed.hostname
    port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)
    endpoint = parsed.path if parsed.path else "/"

    os.makedirs("fuzz-output", exist_ok=True)

    session = Session(
        target=Target(
            connection=SocketConnection(
                host=host,
                port=port,
                proto="tcp"
            )
        ),
        crash_threshold_request=1,
        sleep_time=0.05,
        receive_data_after_fuzz=True,
        fuzz_loggers=[
            FuzzLoggerText(file_name="fuzz-output/fuzz-log.txt"),  # FIXED
        ]
    )

    ######################################
    # REQUEST BLOCK
    ######################################
    s_initialize("HTTP_FUZZ")

    if s_block_start("Request-Line"):
        s_string("GET", fuzzable=True)
        s_delim(" ")
        s_string(endpoint, fuzzable=True)
        s_delim(" ")
        s_string("HTTP/1.1", fuzzable=False)
        s_static("\r\n")
    s_block_end("Request-Line")

    # Standard headers
    def header(name, fuzz=True):
        s_string(name, fuzzable=False)
        s_delim(": ")
        s_string("fuzz", fuzzable=fuzz)
        s_static("\r\n")

    header("Host", fuzz=False)
    header("User-Agent", fuzz=True)
    header("X-Forwarded-For", fuzz=True)
    header("Content-Type", fuzz=True)
    header("Content-Length", fuzz=False)

    s_static("\r\n")

    ######################################
    # JSON BODY FUZZ
    ######################################
    if s_block_start("JSON-Body"):
        s_string("{", fuzzable=False)
        s_string("\"key\":", fuzzable=False)
        s_string("\"FUZZDATA\"", fuzzable=True)
        s_string("}", fuzzable=False)
    s_block_end("JSON-Body")

    session.connect(s_get("HTTP_FUZZ"))
    session.fuzz()

    print("Fuzzing finished. Logs saved in fuzz-output/")

if __name__ == "__main__":
    main()
