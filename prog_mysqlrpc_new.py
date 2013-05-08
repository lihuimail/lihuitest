# -*- coding: utf-8 -*-

import struct
import random
import errno
import time
try:
    import ast
except:
    pass
try:
    import hashlib
except:
    pass

SERVER_VERSION = '\n5.1.23-feihuroger\x00'
FRAME_VERSION = '0.1.0'
MYSQL_TYPENO = {
    'int':      0x03, # FIELD_TYPE_LONG
    'long':     0x03, # FIELD_TYPE_LONG
    'float':    0x05, # FIELD_TYPE_DOUBLE
    'none':     0x06, # FIELD_TYPE_NULL
    'str':      0xfe, # FIELD_TYPE_STRING
    'buffer':   0xfc, # FIELD_TYPE_BLOB
    'datetime': 0x0c, # FIELD_TYPE_DATETIME
    }
MYSQL_CMD_QUERY = '\x03'
MYSQL_CMD_QUIT  = '\x01' # MYSQL CMD QUIT
MYSQL_CMD_PING  = '\x0e' # MYSQL CLIENT PING
RESULT_OK_PACKET = '\x00\x00\x00\x02\x00\x00\x00'

#db
DB={
    'server_version':SERVER_VERSION.strip(),
    'frame_version':FRAME_VERSION,
    }

def get_db():
    global DB
    return DB

#wrap
def wrap_timecall(func):
    def wrap(*args):
        d=get_db()
        a=time.time()
        result = func(*args)
        d['func_'+func.__name__]=str((time.time()-a)*10000)
        return result
    return wrap

###################
class LogicError(Exception):
    def __init__(self, errno, errmsg):
        self.errno = errno
        self.errmsg = errmsg
        self.args = (errno, errmsg)
        return
    def __str__(self):
        return 'LogicError: errno=%d errmsg=%s' % self.args
    def __repr__(self):
        return "LogicError(%d,'%s')" % self.args

#mysql protocol
def auth_check(password, sbuffer, cbuffer, dbname, client_option, max_packet_size):
    try:
        stage1 = hashlib.sha1(password).digest()
        stage2 = hashlib.sha1(stage1).digest()
        stage3 = hashlib.sha1(sbuffer+stage2).digest()
        stage4 = ''.join(map(lambda (x, y): chr(ord(x) ^ ord(y)), zip(stage1, stage3)))
        if stage4==cbuffer:
            return True
        else:
            return False
    except KeyError:
        return False

def get_encode_none():
    return '\xfb' # ascii=251 NULL

def get_encode_str(astr):
    if astr is None:
        return make_encode_none()
    else:
        astrlen = len(astr)
        header = get_encode_int(astrlen)
        return header + astr

def get_encode_int(aint):
    if aint is None:
        return make_encode_none()
    elif aint <= 250:
        return struct.pack("B", aint)
    elif aint >= 251 and aint < 65536:
        return '\xfc'+struct.pack("<H", aint)
    elif aint >= 65536 and aint < 4294967296L:
        return '\xfd'+struct.pack("<I", aint)
    else:
        aint1, aint2 = divmod(aint, 4294967296L)
        return '\xfe'+struct.pack("<II", aint2, aint1)

def get_struct_packet(pkt,sid_func=None):
    len2, len1 = divmod(len(pkt), 65536)
    header = struct.pack("<HBB", len1, len2,sid_func()) #need debug
    result=header+pkt
    return result

def make_struct_simpleok(sid_func=None):
    return get_struct_packet(RESULT_OK_PACKET,sid_func=sid_func)

def make_struct_ok(arows, insertid, server_status, warning_count, message,sid_func=None):
    packet = '\x00'+get_encode_int(arows) + get_encode_int(insertid) + \
            struct.pack("<H", server_status) + struct.pack("<H", warning_count)
    if message:
        packet += get_encode_str(message)
    return get_struct_packet(packet,sid_func=sid_func)

def make_struct_error(errno, sqlstatus, message,sid_func=None):
    assert len(sqlstatus) == 5, 'length of sqlstatus must be 5'
    packet = '\xff'+struct.pack("<H", errno)+'#'+sqlstatus[:5]+message
    return get_struct_packet(packet,sid_func=sid_func)

def make_hand_shake(sid_func=None):
    version = SERVER_VERSION
    thread_id = struct.pack("<I", random.randint(1, 65535))
    sbuffer = ''.join(map(lambda _: chr(random.randint(33, 127)), range(20)))
    buffer_0 = sbuffer[:8]
    buffer_1 = sbuffer[8:]
    server_option = struct.pack("<H", 33288)
    server_language = '\x08'
    server_status = '\x02\x00'
    packet = version+thread_id+buffer_0+'\x00'+server_option+server_language+server_status+'\x00'*13+buffer_1+'\x00'
    return get_struct_packet(packet,sid_func=sid_func),sbuffer

def make_struct_resultset_yield(
        column_list, dataset, 
        database_name = '', table_name = '', origin_table_name = '', server_status = 0, charset = 8,
        sid_func=None
        ):
    yield get_struct_packet(struct.pack("B", len(column_list)),sid_func=sid_func)
    dbname = get_encode_str(database_name)
    tablename = get_encode_str(table_name)
    origintablename = get_encode_str(origin_table_name)
    serverstatus = struct.pack("<H", server_status)
    charset = struct.pack("<H", charset)
    typelist = []
    for (colname, pytype) in column_list:
        columnname = get_encode_str(str(colname))
        typeno = MYSQL_TYPENO[pytype]
        packet = get_encode_str('def')+dbname+tablename+origintablename+columnname+columnname + \
            '\x0c\x08\x00\x00\x00\x00\x00'+struct.pack("B", typeno)+'\x00\x00\x00\x00\x00\x00'
        yield get_struct_packet(packet,sid_func=sid_func)
        typelist.append(pytype)
    eofpacket = '\xfe\x00\x00'+serverstatus
    yield  get_struct_packet(eofpacket,sid_func=sid_func)
    for record in dataset:
        packet = ''
        assert len(record) == len(typelist), "Dataset's column count not equal title column count"
        for pytype, cell in zip(typelist, record):
            if cell is None:
                packet += get_encode_none()
            elif pytype == 'datetime':
                packet += get_encode_str(cell.strftime('%Y-%m-%d %H:%M:%S'))
            else:
                packet += get_encode_str(str(cell))
        yield get_struct_packet(packet,sid_func=sid_func)
    yield get_struct_packet(eofpacket,sid_func=sid_func)

def make_struct_resultset(
        column_list, dataset, 
        database_name = '', table_name = '', origin_table_name = '', server_status = 0, charset = 8,
        sid_func=None
        ):
    result=''
    for v in make_struct_resultset_yield(
            column_list, dataset, 
            database_name = database_name, table_name = table_name, 
            origin_table_name = origin_table_name, server_status = server_status, charset = charset,
            sid_func=sid_func
            ):
        result+=v
    return result

def mysql_auth_check(data,sbuffer,aclmap=None,sid_func=None):
    client_option = struct.unpack("<I", data[:4])[0]
    max_packet_size = struct.unpack("<I", data[4:8])[0]
    charset = data[8]
    assert data[9:32] == '\x00'*23
    zeropos = data[32:].find('\x00')
    zeropos += 32
    username = data[32:zeropos]
    authed=None
    if data[zeropos+1] == '\x14':
        cbuffer = data[zeropos+2:zeropos+22]
        if len(data) > zeropos+22:
            dbname = data[zeropos+22:-1]
        else:
            dbname = 'pymysqlrpc'
    elif data[zeropos+1] == '\x00':
        cbuffer = None
        dbname = None
    else:
        raise ValueError("Auth packet error, %s" % repr(data))
    try:
        password = aclmap.get(username)[0]
        if auth_check(password, sbuffer, cbuffer, dbname, client_option, max_packet_size):
            result=make_struct_ok(0, 0, 2, 0, '',sid_func=sid_func)
            authed = True
        else:
            result=get_struct_packet('\xfe',sid_func=sid_func)
            result+=get_struct_packet('\xff\x15\x04#28000Access denied (password is ERROR)',sid_func=sid_func)
    except KeyError:
        raise ValueError("Auth error, %s" % repr(data))
    return result,authed,username,password

class MysqlBASE(object):
    ####################################
    def set_timeout(self,value=None):
        t=self.get_socket_handle()
        if t is None:
            return None
        t.settimeout(value)
    def get_sid(self):
        if getattr(self,'sid',None) is None:
            self.sid=-1
        self.sid+=1
        return self.sid
    def get_socket_handle(self):
        return getattr(self,'_socket_handle',None)
    def get_socket_address(self):
        return getattr(self,'_socket_address',None)
    def get_socket_data(self):
        return getattr(self,'_socket_data',None)
    def get_server_host(self):
        return getattr(self,'_server_host',None)
    def get_server_port(self):
        return getattr(self,'_server_port',None)
    def get_client_host(self):
        return getattr(self,'_client_host',None)
    def get_client_port(self):
        return getattr(self,'_client_port',None)
    def set_default_timeout(self,value=None):
        self._socket_default_timeout=int(value)
    def get_process_error(self):
        if getattr(self,'_process_error',None) is None:
            self._process_error=0
        self._process_error+=1
        return self._process_error
    def get_default_timeout(self):
        result=getattr(self,'_socket_default_timeout',None)
        return result
    ####################################
    def send(self,value=None):
        raise
    def recv(self,timeout=50,buf=1024):
        raise
    ####################################
    def query(self, cmdarg):
        arg = cmdarg[1:].strip()
        if arg.find(' ') != -1:
            query, param = arg.split(' ', 1)
            query = query.strip().lower()
            param = param.strip()
            if param[-1] == ';':
                param = param[:-1]
        else:
            self.send(make_struct_simpleok(sid_func=self.get_sid))
            return None
        if query == 'call': # 存储过程调用
            try:
                reterror, retvar = self.sql_call_func(param, self.get_acl().get(self.username)[1])
                if reterror:
                    self.send(make_struct_error(500, "HY101", "func call 1: "+str(retvar)+":" + param[:100],sid_func=self.get_sid))
                    return None
                if not retvar:
                    self.send(make_struct_ok(1, 0, 0, 0, "",sid_func=self.get_sid))
                else:
                    collist, dataset =retvar
                    for v in make_struct_resultset_yield(collist, dataset,sid_func=self.get_sid):
                        self.send(v)
            except LogicError, ex:
                self.send(make_struct_error(ex.errno, "HY100", ex.errmsg,sid_func=self.get_sid))
            except Exception, ex:
                self.send(make_struct_error(500, "HY102", "func call 2: --"+str(ex)+"--:" + param[:100],sid_func=self.get_sid))
        else:
            getattr(self,'sql_'+query+'_func',self.sql_other_func)(param)
    def sql_set_func(self,*args,**kwargs):
        self.send(make_struct_simpleok(sid_func=self.get_sid))
    def sql_show_func(self,*args,**kwargs):
        param=args[0]
        if param.lower()=='status':
            collist=[('key','str'),('val','str')]
            dataset=[]
            for k,v in DB.items():
                if type(v)==list:
                    v=','.join([str(v0) for v0 in v])
                dataset.append((k,v))
            self.send(make_struct_resultset(collist, dataset,sid_func=self.get_sid))
        else:
            self.send(make_struct_simpleok(sid_func=self.get_sid))
    def sql_select_func(self,*args,**kwargs):
        param=args[0]
        if param.lower().startswith('@@max_allowed_packet'):
            collist, dataset = [(param.lower().split(' ',1)[0],'int')],[(268435456,)]
            self.send(make_struct_resultset(collist, dataset,sid_func=self.get_sid))
        elif param.lower().startswith('@@version_comment'):
            collist, dataset = [(param.lower().split(' ',1)[0],'str',)],[('debian',)]
            self.send(make_struct_resultset(collist, dataset,sid_func=self.get_sid))
        elif param.lower().startswith('@@test'):
            collist, dataset = [(param.lower().split(' ',1)[0],'str',)],[('1'*1000*1000,)]
            self.send(make_struct_resultset(collist, dataset,sid_func=self.get_sid))
        else:
            self.send(self.make_struct_simpleok(sid_func=self.get_sid))
    def sql_other_func(self,*args,**kwargs):
        self.send(make_struct_simpleok(sid_func=self.get_sid))
    def sql_call_func(self, req, funcdict):
        offset = req.find('(')
        if offset == -1:
            return 1, "--'(' NOT exist--"
        paramlist = []
        try:
            paramast = ast.literal_eval(req[offset:])
            if type(paramast) == tuple:
                paramlist = paramast
            else:
                paramlist.append(paramast)
        except Exception, ex:
            return 2, '--'+str(ex)+'--'
        if req[:offset] in funcdict:
            return 0, funcdict[req[:offset]](*paramlist)
        else:
            return 3, "--function NOT exist--"
    def set_acl(self,acl):
        self._acl=acl
    def get_acl(self):
        return self._acl
    def set_option(self,aclmap=None,time_connect=None,time_active=None):
        self.set_acl(aclmap)
        self._time_connect=time_connect
        self._time_active=time_active

#gevent
class GeventHandler(MysqlBASE):
    def process(self):
        if getattr(self,'_time_active',None):
            self.set_timeout(value=getattr(self,'_time_active',None))
        timeout=getattr(self,'_time_connect',None) or 50
        if getattr(self,'buf',None) is None:
            self.buf = ""
        send_ver,sbuffer=make_hand_shake(sid_func=self.get_sid)
        self.send(send_ver)
        while True:
            a=self.recv(timeout=timeout,buf=1024)
            if not a:
                break
            self.buf += a
            if not getattr(self,'authed',None) and len(self.buf) > 1024:
                break
            if not getattr(self,'packetheader',None):
                if len(self.buf) >= 4:
                    len1, len2, self.sid = struct.unpack("<HBB", self.buf[:4])
                    length = (len2 << 16) + len1
                    self.packetheader = True
                else:
                    continue
            body = self.buf[4:]
            if len(body) < length:
                continue
            cmdarg = body[:length]
            self.buf = body[length:]
            self.packetheader = False
            if not getattr(self,'authed',None):
                send_value,self.authed,self.username,password=mysql_auth_check(
                    cmdarg,sbuffer,aclmap=self.get_acl(),sid_func=self.get_sid
                    )
                self.send(send_value)
            elif cmdarg[0] == MYSQL_CMD_QUIT:
                break
            elif cmdarg[0] == MYSQL_CMD_PING:
                self.send(make_struct_simpleok(sid_func=self.get_sid))
            elif cmdarg[0] == MYSQL_CMD_QUERY:
                self.query(cmdarg)
            else:
                self.send(make_struct_simpleok(sid_func=self.get_sid))
        print 'connnect close'
    def __init__(self,*args,**kwargs):
        self._timeout=kwargs.get('timeout')
        if self._timeout is None:
            self._timeout=10
        self._socket_handle=kwargs.get('socket_handle')
        self._socket_address=kwargs.get('socket_address')
        self._server_host=kwargs.get('server_host')
        self._server_port=kwargs.get('server_port')
        if self._server_host is None:
            self._server_host,self._server_port=self._socket_handle.getsockname()
        self._client_host,self._client_port=self._socket_handle.getpeername()
    def send(self,value=None):
        if value is None or value=='':
            return None
        try:
            self.get_socket_handle().sendall(value)
            result=True
        except:
            self.get_process_error()
            result=False
            #raise
            print 'send error'
        return result
    def recv(self,timeout=50,buf=1024):
        try:
            result = self.get_socket_handle().recv(buf)
        except:
            print 'recv error'
            #raise
            result=None
        if  result is None or result=='':
            if self.get_process_error()>timeout:
                result=False
            else:
                result=None
        return result

class GeventFunc(object):
    def __init__(self,aclmap=None,time_connect=None,time_active=None):
        self._aclmap=aclmap
        self._time_connect=time_connect
        self._time_active=time_active
    def __call__(self,s_socket, s_address):
        r=GeventHandler(socket_handle=s_socket,socket_address=s_address)
        r.set_option(aclmap=self._aclmap,time_connect=self._time_connect,time_active=self._time_active)
        r.process()

def gevent_start_server(host=None,port=None,aclmap=None,time_connect=None,time_active=None):
    from gevent.server import StreamServer
    func=GeventFunc(aclmap=aclmap,time_connect=time_connect,time_active=time_active)
    f=StreamServer((host,int(port)), func)
    f.serve_forever()

####################################################
@wrap_timecall
def add(a,b):
    return [('sum','int'),],[(a+b,), ]
@wrap_timecall
def test1():
    def test1_yield():
        for v in range(10):
            yield (v,)
    return [('test1','int'),],test1_yield()
ACL= {"testuser": ["testpass",{"myadd": add,'test1':test1}],
      "root":["rootpass",{}]
    }
def test_server():
    host='127.0.0.1'
    port=44444
    gevent_start_server(
        host=host,port=port,
        aclmap=ACL,time_connect=None,time_active=None
        )

if __name__=='__main__':
    test_server()
