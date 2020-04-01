# Usage: <script> <csv file> [-t]
# [-t] - (optionanl) Print time in seconds, ms, us, etc.


import csv
import sys


headers = {}
titles = []
perthreadtimes = {}
fmttime = False


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


def transformtime(time):
    if not fmttime: return("{:,}".format(time))

    timestr = ""

    #minutes = time//6*10**10
    #if minutes >= 1:
    #    timestr += str(minutes) + " m"
    #time %= 6*10**10

    s = time//10**9
    if s >= 1:
        timestr += str(s) + "s "
    time %= 10**9

    ms = time//10**6
    if ms >= 1:
        timestr += str(ms) + "ms "
    time %= 10**6

    us = time//10**3
    if us >= 1:
        timestr += str(us) + "us "
    time %= 10**3

    timestr += str(time) + "ns"

    return(timestr)


def justifytext():
    w1, w2, w3 = 50, 25, 12
    for i in range(len(titles)):
        if i == 0: # Larger padding for API names
            titles[i] = titles[i].rjust(w1)
        elif i == 1 or i == 2:
            titles[i] = titles[i].rjust(w2)
        else:
            titles[i] = titles[i].rjust(w3)

    for tid in perthreadtimes:
        for row in perthreadtimes[tid]:
            for i in range(len(row)):
                if i == 0: # Larger padding for API names
                    row[i] = row[i].rjust(w1)
                elif i == 1 or i == 2:
                    row[i] = transformtime(int(row[i])).rjust(w2)
                else:
                    row[i] = "{:,}".format(int(row[i])).rjust(w3)


def prettyprint():
    print("%s: %s\t%s: %s\t%s: %s" %
            ("PID", headers["pid"],
             "EXECUTABLE", headers["executable"],
             "HOSTNAME", headers["hostname"]))
    print("%s: %s" % ("TIME", headers["time"]))

    print(' '.join(titles))

    for tid in perthreadtimes:
        print("THREAD ID: %s" % tid)

        for row in perthreadtimes[tid]:
            print(' '.join(row))


if __name__ == "__main__":

    if len(sys.argv) not in [2,3]:
        print("Usage: %s <csv file> [-t]" % sys.argv[0])
        print("[-t] - (optionanl) Print time in seconds, ms, us, etc.")

    if "-t" in sys.argv:
        fmttime = True

    readfromfile()
    #print(titles)
    justifytext()
    prettyprint()

