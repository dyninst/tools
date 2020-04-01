import csv
import sys


headers = {}
titles = []
perthreadtimes = {}


def readfromfile():
    with open(sys.argv[1], 'r') as resultsfile:
        results = list(csv.reader(resultsfile))

        headerlist = results[0]
        for rawheader in headerlist:
            key, value = rawheader.split('=')
            headers[key] = value

        curthread = None
        for i in range(1, len(results)):
            row = results[i]

            if row == []: continue
            # print('r =', row)

            if row[0][0] == '%':
                row[0] = row[0][2:]
                global titles
                titles = row
            elif row[0].startswith("tid="):
                curthread = row[0][4:]
                perthreadtimes[curthread] = []
            else:
                perthreadtimes[curthread].append(row)


def justifytext():
    for i in range(len(titles)):
        if i == 0:
            titles[i] = titles[i].rjust(60)
        else:
            titles[i] = titles[i].rjust(15)

    for tid in perthreadtimes:
        for row in perthreadtimes[tid]:
            for i in range(len(row)):
                if i == 0:
                    row[i] = row[i].rjust(60)
                else:
                    row[i] = "{:,}".format(int(row[i])).rjust(15)


def prettyprint():
    print("%s: %s\t%s: %s\t%s: %s" %
            ("PID", headers["pid"],
             "EXECUTABLE", headers["executable"],
             "HOSTNAME", headers["hostname"]))
    print("%s: %s" % ("TIME", headers["time"]))

    print('\t'.join(titles))

    for tid in perthreadtimes:
        print("THREAD ID: %s" % tid)

        for row in perthreadtimes[tid]:
            print('\t'.join(row))


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: %s <csv file>" % sys.argv[0])

    readfromfile()
    #print(titles)
    justifytext()
    prettyprint()

