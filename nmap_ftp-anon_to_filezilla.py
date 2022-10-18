# nmap_ftp-anon_to_filezilla 0.1 by Jaime Alekos (contacto[at]jaimealekos[dot]com)

import argparse
from xml.etree import ElementTree

# Takes ftp-anon positve results from a nmap -oX file and writes a FileZilla sites xml with them

parser = argparse.ArgumentParser()
parser.add_argument('--nmapxml', type=str, required=True, help="path+filename of nmap xml results source file")
parser.add_argument('--fzxml', type=str, required=True, help="path+filename of filezilla xml sites output file")
args = parser.parse_args()

# Takes nmap xml results file and returns a list of positive ftp-anon results, each one containing:
# [0]="ip:port" or "ip:port hostname" if reverse DNS was succesful
# [1]=ftp-anon output

def nmap_ftpanon_extractor(nmapXml):
    tree=ElementTree.parse(nmapXml)
    nest1=tree.getroot()
    foundports=list([])
    for e1 in nest1:    
        if e1.tag=="host": # gets only active hosts and discards hosthints 
            for e2 in e1.iter():            
                if e2.tag=="address": # grabs address in case we need it later
                    hostaddr=e2.attrib.get('addr') 
                if e2.tag=="hostname": # grabs hostname in case we need it later
                        for e2b in e2.iter():
                            hostname=e2b.attrib.get('name')
                if e2.tag=="ports": # gets inside ports
                    for e3 in e2.iter():
                        if e3.tag=="port": # gets inside port
                            hostport=e3.attrib.get('portid') # grabs port number 
                            for e4 in e3.iter():
                                if e4.tag=="state": # gets inside state
                                    for e5 in e4.iter():
                                        if e5.attrib.get('state')=="open": # tries every open port looking for ftp-anon
                                            savePort=["a","b"]
                                            # saves the entry to check it later against ftp-anon
                                            try:
                                                savePort[0]=hostaddr+":"+hostport+" "+hostname 
                                            except:
                                                savePort[0]=hostaddr+":"+hostport
                        if e3.tag=="script": # gets inside script
                            for e6 in e3.iter():
                                if e6.attrib.get('id')=="ftp-anon": # if ftp-anon exists, it means the scan worked
                                    savePort[1]=e6.attrib.get('output')
                                    foundports.append(savePort)
    return foundports

def fzFtp(ipHost): # takes "ip:port" or "ip:port reversedns" and returns fz xml object
    ftp=("            <Server>\n")
    ftp+=("					<Host>"+ipHost.split(" ")[0].split(":")[0]+"</Host>\n")
    ftp+=("					<Port>"+ipHost.split(" ")[0].split(":")[1]+"</Port>\n")
    ftp+=("					<Protocol>0</Protocol>\n")
    ftp+=("					<Type>0</Type>\n")
    ftp+=("					<User>anonymous</User>\n")
    ftp+=("					<Pass>anonymous@guest.com</Pass>\n")
    ftp+=("					<Logontype>1</Logontype>\n")
    ftp+=("					<PasvMode>MODE_DEFAULT</PasvMode>\n")
    ftp+=("					<EncodingType>Auto</EncodingType>\n")
    ftp+=("					<BypassProxy>0</BypassProxy>\n")
    if " " in ipHost: ftp+=("					<Name>"+ipHost.split(" ")[0]+" ("+ipHost.split(" ")[1]+")</Host>\n")
    else: ftp+=("					<Name>"+ipHost.split(" ")[0]+"</Host>\n")                
    ftp+=("					<SyncBrowsing>0</SyncBrowsing>\n")
    ftp+=("					<DirectoryComparison>0</DirectoryComparison>\n")
    ftp+=("				</Server>\n")    
    return ftp

def fzFolder(folderName, ftps):
    folder=("	    <Folder expanded=\"1\">"+folderName+"\n")    
    for ftp in ftps: folder+=fzFtp(ftp[0])
    folder+=("	    </Folder>\n")
    return folder

ftps=nmap_ftpanon_extractor(args.nmapxml)
file=open(args.fzxml,"w")
file.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
file.write("<FileZilla3>\n")
file.write("	<Servers>\n")
file.write(fzFolder("nmap",ftps))
file.write("	</Servers>\n")    
file.write("</FileZilla3>\n")
file.close