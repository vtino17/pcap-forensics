from pcap_forensics.cli import build_parser, run


def entry_point():
    parser = build_parser()
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    entry_point()
