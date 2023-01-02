#!/usr/bin/python3

import subprocess as sp
import sys
import os
import logging
from argparse import ArgumentParser
from collections import namedtuple

def excelFormat(record):
    return record

Column = namedtuple('Column', ['name', 'pos', 'get'])

C_FILENAME              = Column(name='filename',                   pos='A', get=lambda x: excelFormat(x['filename']))
C_CNT_DLOPEN            = Column(name='# dlopen',                   pos='C', get=lambda x: x['dlopenCount'])
C_CNT_DLOPEN_STR        = Column(name='# dlopen (w/ static str)',   pos='D', get=lambda x: x['dlopenWithStaticString'])
C_CNT_DLMOPEN           = Column(name='# dlmopen',                  pos='E', get=lambda x: x['dlmopenCount'])
C_CNT_DLMOPEN_STR       = Column(name='# dlmopen (w/ static str)',  pos='F', get=lambda x: x['dlmopenWithStaticString'])
C_HAS_DLOPEN_DLMOPEN    = Column(name='has dlopen/dlmopen',         pos='B', get=lambda x:'"=IF(OR({0}{2}>0,{1}{2}>0),1,0)"'.format(C_CNT_DLOPEN.pos, C_CNT_DLMOPEN.pos, x['row']))
C_CNT_DLSYM             = Column(name='# dlsym',                    pos='H', get=lambda x: x['dlsymCount'])
C_CNT_DLSYM_STR         = Column(name='# dlsym (w/ static str)',    pos='I', get=lambda x: x['dlsymWithStaticString'])
C_CNT_DLVSYM            = Column(name='# dlvsym',                   pos='J', get=lambda x: x['dlvsymCount'])
C_CNT_DLVSYM_STR        = Column(name='# dlvsym (w/ static str)',   pos='K', get=lambda x: x['dlvsymWithStaticString'])
C_HAS_DLSYM_DLVSYM      = Column(name='has dlsym/dlvsym',           pos='G', get=lambda x:'"=IF(OR({0}{2}>0,{1}{2}>0),1,0)"'.format(C_CNT_DLSYM.pos, C_CNT_DLVSYM.pos, x['row'])) 
C_CNT_DLSYM_MAP         = Column(name='# dlsym/dlvsym mapped',      pos='L', get=lambda x: x['dlsymMapped'])
C_CNT_DLSYM_RTLD_DEF    = Column(name='# dlsym/dlvsym RTLD_DEFAULT',pos='M', get=lambda x: x['dlsymWithRTLD_DEFAULT'])
C_CNT_DLSYM_RTLD_NXT    = Column(name='# dlsym/dlvsym RTLD_NEXT',   pos='N', get=lambda x: x['dlsymWithRTLD_NEXT'])
C_CNT_DLSYM_ATTR        = Column(name='# dlsym/dlvsym attributed',  pos='O', get=lambda x: x[C_CNT_DLSYM_ATTR.name])

fields = [
    C_FILENAME, C_HAS_DLOPEN_DLMOPEN, C_CNT_DLOPEN, C_CNT_DLOPEN_STR, C_CNT_DLMOPEN, C_CNT_DLMOPEN_STR,
    C_HAS_DLSYM_DLVSYM, C_CNT_DLSYM, C_CNT_DLSYM_STR, C_CNT_DLVSYM, C_CNT_DLVSYM_STR,
    C_CNT_DLSYM_MAP, C_CNT_DLSYM_RTLD_DEF, C_CNT_DLSYM_RTLD_NXT, C_CNT_DLSYM_ATTR ]

def find_tag_value(inp):
    if '=' not in inp:
        return None, None
    tag, rem = inp.split('=', 1)
    val = None
    if rem.startswith('['):
        val, rem = rem.split(']', 1)
        val += ']'
        rem = rem[1:]
    elif '|' in rem:
        val, rem = rem.split('|', 1)
    else:
        val = rem
        rem = ''
    return tag, val, rem

def split_kvp(line):
    _, contents = line.strip().split('=', 1)
    contents = contents.strip()[1:-1]
    ret = {}
    while contents:
        tag, val, contents = find_tag_value(contents)
        ret[tag] = val
    return ret

def split_digest(line):
    raw_digest = split_kvp(line)
    digest = { x : int(y) for x, y in raw_digest.items() }
    return None if sum(val for _, val in digest.items()) == 0 else digest

def main():
    logging.basicConfig(level=logging.INFO)
    parser = ArgumentParser(
        prog='dlsonic test utility',
        description='run tests and generate reports', 
        epilog='all options are compulsory!')
    parser.add_argument('-c', '--csv-output', required=True)
    parser.add_argument('-r', '--raw-output', required=True)
    parser.add_argument('-i', '--input', required=True)
    parser.add_argument('-d', '--dlsonic')

    args = parser.parse_args()
    if not os.path.exists(args.input):
        logging.error('input file does not exist')
        return

    # by default we assume the binary is in current working directory    
    binary = 'dlsonic'

    # user can provide an alternate binary this way
    if args.dlsonic:
        binary = args.dlsonic.strip()

    raw_output = args.raw_output.strip()
    
    with open(raw_output, 'w') as raw: pass

    logging.info('Processing input file list: {}'.format(args.input.strip()))
    with open(args.input.strip()) as filelist:
        for line in filelist:
            filename = line.strip()
            if not os.path.exists(filename):
                logging.warning('file ({}) does not exist'.format(filename))
            sp.call('./{} {} >> {} 2>&1'.format(binary, filename, raw_output), shell=True)
    
    info_by_file = {}
    with open(raw_output, 'rb') as raw_out:
        for line_us in raw_out:
            try:
                line = str(line_us.strip().decode("utf-8") )
                if not line.startswith('DIGEST') and not line.startswith('CALLDETAIL'):
                    continue
                
                filename = line.split(':')[1].split('=')[0]

                if filename not in info_by_file:
                    info_by_file[filename] = []
                info_by_file[filename].append(line)
            except:
                pass
 
    total_files = len(info_by_file)

    logging.info('# files processed: {}'.format(total_files))

    processed_digests = []
    for filename in info_by_file:
        vals = info_by_file[filename]
        file_digest = {C_CNT_DLSYM_ATTR.name : 0}
        calldetails = {}
        found_digest = False
        for line in vals:
            if 'DIGEST' in line:
                digest = split_digest(line)
                if not digest:
                    continue
                found_digest = True
                digest['filename'] = filename
                digest['row'] = len(processed_digests) + 2 # since first row is reserved for header
                file_digest.update(digest)
            if 'CALLDETAIL' in line:
                kvps = split_kvp(line)
                calldetails[kvps['Id']] = kvps
        
        if found_digest:
            for _, entry in calldetails.items():
                if entry['Type'] not in ['dlsym', 'dlvsym']:
                    continue
                if entry['Param'] == '<unknown>':
                    continue
                if entry['Handle'] in ['<unknown>', 'RTLD_DEFAULT', 'RTLD_NEXT']:
                    continue
                parent = calldetails.get(entry['Handle'], None)
                if not parent:
                    continue
                if parent['Type'] not in ['dlopen', 'dlmopen']:
                    continue
                if parent['Param'] == "<unknown>":
                    continue
                file_digest[C_CNT_DLSYM_ATTR.name] += 1
            processed_digests.append(file_digest)


    if not processed_digests:
        logging.warning('No useful results found')
        return

    with open(args.csv_output.strip(), 'w') as csv_out:
        csv_out.write(','.join([x.name for x in fields])+'\n')
        num_files_with_dlsyms = 0
        num_files_with_dlopens = 0
        for digest in processed_digests:
            row_val = [str(x.get(digest)) for x in fields]
            csv_out.write(','.join(row_val)+'\n')
            num_files_with_dlsyms += 1 if sum([int(C_CNT_DLSYM.get(digest)), int(C_CNT_DLVSYM.get(digest))]) > 0 else 0
            num_files_with_dlopens += 1 if sum([int(C_CNT_DLOPEN.get(digest)), int(C_CNT_DLMOPEN.get(digest))]) > 0 else 0

        x_bgn = processed_digests[0]['row']
        x_end = processed_digests[-1]['row']

        line = ['Total'] + ["=SUM({0}{1}:{0}{2})".format(fld.pos, x_bgn, x_end) for fld in fields[1:]]
        csv_out.write(','.join(line)+'\n')

        # write global stats
        csv_out.write('Global Statistics Begin\n')
        csv_out.write('Total Files Processed,{}\n'.format(total_files))
        csv_out.write('% files with dlopen/dlmopen,{}\n'.format(num_files_with_dlopens*1.0/total_files*100))
        csv_out.write('% files with dlsym/dlvsym,{}\n'.format(num_files_with_dlsyms*1.0/total_files*100))
        csv_out.write('Global Statistics End\n')


    logging.info('Completed Writing: {}'.format(args.csv_output.strip()))

if __name__ == '__main__':
    main()
