#!/usr/bin/env python3
#
# Description   :- Generate self signed CA and certificates.
# Author        :- Muhammed Iqbal <iquzart@hotmail.com>
#


import random
import os
from datetime import datetime
from OpenSSL import crypto



def create_CA(root_ca_path, key_path):
    ''' Create CA and Key'''
    
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 4096)


    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    ca_cert.set_serial_number(random.randint(50000000, 100000000))


    ca_subj = ca_cert.get_subject()
    ca_subj.countryName = input("Country Name (2 letter code) [XX]: ")
    ca_subj.stateOrProvinceName = input("State or Province Name (full name) []: ")
    ca_subj.localityName = input("Locality Name (eg, city) [Default City]: ")
    ca_subj.organizationName = input("Organization Name (eg, company) [Default Company Ltd]: ")
    ca_subj.organizationalUnitName = input("Organizational Unit Name (eg, section) []: ")
    ca_subj.commonName = input("Common Name (eg, your name or your server's hostname) []: ")
    ca_subj.emailAddress = input("Email Address []: ")
    
    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_key)

    ca_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
        #crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyCertSign, cRLSign"),
    ])


    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10*365*24*60*60)

    ca_cert.sign(ca_key, 'sha256')

    # Save certificate
    with open(root_ca_path, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode("utf-8"))

    # Save private key
    with open(key_path, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode("utf-8"))
        
    
        
def load_CA(root_ca_path, key_path):
    ''' Load CA and Key'''

    with open(root_ca_path, "r") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(key_path, "r") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    return ca_cert, ca_key


def CA_varification(ca_cert):  
    ''' Varify the CA certificate '''

    ca_expiry = datetime.strptime(str(ca_cert.get_notAfter(), 'utf-8'),"%Y%m%d%H%M%SZ")
    now = datetime.now()
    validity = (ca_expiry - now).days
    print ("CA Certificate valid for {} days".format(validity))
    
            
def create_cert(ca_cert, ca_subj, ca_key, client_cn):
    ''' Create Client certificate '''
    
    client_key = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA, 4096)

    client_cert = crypto.X509()
    client_cert.set_version(2)
    client_cert.set_serial_number(random.randint(50000000, 100000000))

    client_subj = client_cert.get_subject()
    client_subj.commonName = client_cn
    
    client_cert.set_issuer(ca_subj)
    client_cert.set_pubkey(client_key)

    client_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid", issuer=ca_cert),
        #crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=client_cert),
    ])
    
    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(365*24*60*60)

    client_cert.sign(ca_key, 'sha256')


    with open(client_cn + ".crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode("utf-8"))


    with open(client_cn + ".key", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))

def client_varification():
    pass
    

        
def main():
    
    '''Create self signed certificates'''

    key_path = "CA/ca.key"
    root_ca_path = "CA/ca.crt"
    
    
    if not os.path.exists('CA'):
        print ("Creating CA driectory")
        os.makedirs('CA')
        
    if not os.path.exists(root_ca_path):
        print ("Creating CA Certificate, Please provide the values")
        create_CA(root_ca_path, key_path)
        print ("Created CA Certificate")
        ca_cert, ca_key = load_CA(root_ca_path, key_path)
        CA_varification(ca_cert)
    else:
        print ("CA certificate has been found as {}".format(root_ca_path))
        ca_cert, ca_key = load_CA(root_ca_path, key_path)
        CA_varification(ca_cert)
    

    while True:    
        client_cn = input("Client Certificate CN: ")
        if client_cn != '':
            break
        else:
            print ("Please provide a valid CN for client certificate")
            
    subject = ca_cert.get_subject()
    create_cert(ca_cert, subject, ca_key, client_cn)
    
if __name__ == "__main__":
    main()