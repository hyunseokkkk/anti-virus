# -*- coding: utf-8 -*-

import sys
import os
import hashlib
import time
import zlib
import StringIO
import scanmod
import curemod
import imp 

#파일 크기, 파일 md5, 파일 종류

VirusDB = []
vdb = [] #MD5용
sdb = [] #특정 위치 검색법용
vsize = []
def DecodeKMD(fname):
    try:
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()
        
        buf2 = buf[:-32]
        fmd5 = buf[-32:]
        
        f = buf2
        for i in range(3):
            md5 = hashlib.md5()
            md5.update(f)
            f = md5.hexdigest()
        
        if f != fmd5 : 
            raise SystemError
        
        buf3 = ''
        
        for c in buf2[4:]:
            buf3 += chr(ord(c)^0xFF)
        
        buf4 = zlib.decompress(buf3)
        return buf4
    except:
        pass
    
    return None
        
def LoadVirusDB() :
    buf = DecodeKMD('virus.kmd')
    fp = StringIO.StringIO(buf)
    
    while True:
        line = fp.readline()
        if not line : break
        
        line = line.strip()
        VirusDB.append(line)
        
    fp.close()



def MakeVirusDB():
    for pattern in VirusDB:
        t = []
        v = pattern.split(':')
  
        scan_func = v[0]
        cure_func = v[1]
        
        if scan_func == 'ScanMD5':
        
            t.append(v[3])
            t.append(v[4])
            vdb.append(t)

            size = int(v[2])
            if vsize.count(size) == 0:
                vsize.append(size)
        
        if scan_func == 'ScanStr':
            t.append(int(v[2]))
            t.append(v[3])
            t.append(v[4])
            sdb.append(t)            


if __name__ == '__main__' : 
    
    # start = time.time()
    
    LoadVirusDB()
    # print(VirusDB)
    MakeVirusDB()
    
    if len(sys.argv) != 2:
        print('Usage : antivirus.py [file]')
        sys.exit(0)

    fname = sys.argv[1]
    
    try : 
        m = 'scanmod'
        f, filename, desc = imp.find_module(m, [''])#현재 폴더에서 모듈을 찾음
        module = imp.load_module(m, f, filename,desc)#찾은 모듈 로딩
        #진단 함수 호출 명령어 구성
        cmd = 'ret, vname = module.ScanVirus(vdb, vsize, sdb, fname)'
        exec(cmd)
    except ImportError:
        ret, vname = scanmod.ScanVirus(vdb, vsize, sdb, fname)
    
    if ret == True:
        print('%s : %s' %(fname, vname))
        curemod.CureDelete(fname) #파일을 삭제
    else:
        print('%s : ok' % (fname))

        

