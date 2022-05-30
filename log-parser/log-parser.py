import argparse


def main(ftarget, foutput):
    dropped_ftargets = 0
    protected_ftargets = 0
    global_lines = 0
    tfile = open(ftarget, 'r')
    input = tfile.readlines()

    for _, line in enumerate(input):
        if "patch" in line:
            protected_ftargets += 1
            global_lines += 1
        if "dropped" in line:
            dropped_ftargets += 1
            global_lines += 1

    percentage = (dropped_ftargets / global_lines) * 100

    ofile = open(foutput, 'w')
    ofile.write(f"\nFinal Log Report: " +
                f"\nTotal count for the attacked ftargets is: {global_lines}" +
                f"\nDropped ftargets count is: {dropped_ftargets}" +
                f"\nftargets, that are protected for the exploit: {protected_ftargets}" +
                f"\nDropped percentage is: {percentage}%")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Description of your program')
    parser.add_argument('-t', '--target', type=str, help='Target Logs File to Parse', required=True)
    parser.add_argument('-o', '--output', help='Output File to Place Result', required=True)
    args = vars(parser.parse_args())

    main(args['target'], args['output'])
