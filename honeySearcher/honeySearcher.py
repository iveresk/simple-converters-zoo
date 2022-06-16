import sys


def usage():
    print(f'''
            It's the simplest check for your target file with IPs for honeypot presence.
            The honeypots.txt are collected from Censys.io for the RU and BY region.  
            How to use te application:
            python3 honeySearcher.py <target_file> [OPTIONAL]<honeypot_dictionary> <output_file>
            
            The only required name is a target file name.
            If dictionary is empty - it will use censys one.
            If output_file is empty it will write to output.txt

    ''')


def main(target, dictions, output):
    res = []
    f = open(target, "r")
    lines = f.readlines()

    f1 = open(dictions, "r")
    dicts = f1.readlines()
    for line in lines:
        is_black = False
        for diction in dicts:
            if line == diction:
                is_black = True
                break
        if not is_black:
            res.append(line)
    fo = open(output, "w")
    for line in res:
        fo.writelines(line)


if __name__ == '__main__':
    try:
        targets = sys.argv[1]
    except:
        usage()
        exit(0)
    try:
        dictionary = sys.argv[2]
    except:
        dictionary = "honeypots"
    try:
        output = sys.argv[3]
    except:
        output = "output.txt"
    main(targets, dictionary, output)
