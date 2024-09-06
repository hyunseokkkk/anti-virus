# -*- coding: utf-8 -*-

import hashlib
import os

def SearchVDB(vdb, fmd5):
    
    for t in vdb:
        if t[0] == fmd5:
            return True, t[1]
        
    return False, ''
def ScanMD5(vdb, vsize, fname):
    ret = False #악성코드 발견 유무
    vname = '' #발견된 악성코드 명
    
    size = os.path.getsize(fname)
    if vsize.count(size):
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()
        
        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()
        
        # print(fmd5)
        
        ret, vname = SearchVDB(vdb, fmd5)

    return ret, vname

def ScanStr(fp, offset, mal_str) : 
    size = len(mal_str)
    
    fp.seek(offset)
    buf = fp.read(size)
    # print(buf)
    if buf == mal_str :
        return True
    else :
        return False
    
def ScanVirus(vdb, vsize, sdb, fname):
    print('[*] New ScanVirus')
    
    
    #MD5
    ret, vname = ScanMD5(vdb, vsize, fname)
    if ret == True :
        return ret, vname
    
    
    #특정 위치 검색법
    fp = open(fname, 'rb')
    for t in sdb : 
        if ScanStr(fp, t[0], t[1]) == True:
            ret = True
            vname = t[2]
            break
        
    fp.close()
    
    return ret, vname