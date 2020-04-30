# Digital Certificate Generator

### About
The script created to ease the process of creating self signed certificates. It will create both CA and Server/Client certificates.

Version: 3
Encription: Sha256 with RSA Encription(4096 bit)

### Create Certificate
CA cenrtificate and key will be store under CA directory. 

```
python3 digital-cert.py
```

### Sample output
```
Creating CA driectory
Creating CA Certificate, Please provide the values
Country Name (2 letter code) [XX]: AE
State or Province Name (full name) []: Dubai
Locality Name (eg, city) [Default City]: Emaar Square
Organization Name (eg, company) [Default Company Ltd]: XYZ Company
Organizational Unit Name (eg, section) []: Information Technology
Common Name (eg, your name or your server's hostname) []: XYZ Company SS CA
Email Address []: email@xyz.ae
Created CA Certificate
CA Certificate valid for 3649 days
Client Certificate CN: svc1.xyz.ae
```


```
CA  digital-cert.py  README.md  requirements.txt  svc1.xyz.ae.crt  svc1.xyz.ae.key
```