import subprocess as sp
import sys
import os
import logging
from argparse import ArgumentParser
from collections import namedtuple

def main():
    logging.basicConfig(level=logging.INFO)
    parser = ArgumentParser(
        prog='dlsonic test utility',
        description='run tests and generate reports', 
        epilog='please read the code')
    parser.add_argument('-c', '--csv-output')
    parser.add_argument('-r', '--raw-output')
    parser.add_argument('-i', '--input')

    args = parser.parse_args()
    if not os.path.exists(args.input):
        logging.error('input file does not exist')
        return

    raw_output = args.raw_output.strip()
    
    with open(raw_output, 'w') as raw: pass

    logging.info('Processing input file list: {}'.format(args.input.strip()))
    with open(args.input.strip()) as filelist:
        for line in filelist:
            filename = line.strip()
            if not os.path.exists(filename):
                logging.warning('file ({}) does not exist'.format(filename))
            sp.call('./dlsonic {} >> {} 2>&1'.format(filename, raw_output), shell=True)
    
    digests = []
    with open(raw_output, 'rb') as raw_out:
        for line in raw_out:
            if 'DIGEST' in str(line):
                digests.append(str(line.strip()))
    
    logging.info('# available digests: {}'.format(len(digests)))
    processed_digests = []
    for digest in digests:
        header, contents = digest.split('=', 1)
        contents = contents.strip()[1:-2]
        if sum([int(x.split('=')[1]) for x in contents.split('|')]) > 0:
            proc_dict = {
                x.split('=')[0] : int(x.split('=')[1]) for x in contents.split('|')
            }
            proc_dict.update(File = header.split(':')[1].strip())
            processed_digests.append(proc_dict)

    if not processed_digests:
        logging.warning('No useful results found')
        return

    with open(args.csv_output.strip(), 'w') as csv_out:
        header_elems = ['File'] + [key for key in processed_digests[0] if key != 'File']
        csv_out.write(','.join(header_elems) + '\n')
        for writable_digest in processed_digests:
            csv_out.write(','.join([str(writable_digest[key]) for key in header_elems]) + '\n')

    logging.info('Completed Writing: {}'.format(args.csv_output.strip()))

if __name__ == '__main__':
    main()