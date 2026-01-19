# Guide to create certificate chain using XCA

## 0. Install and open XCA

You can install using you package manager or downloading from [this source](https://hohnstaedt.de/xca/index.php/download).

After opening XCA, create a new database.

## 1. Create root certificate 

Click on `New Certificate`, and fill the fields as shown in the following images:

![Page 1](images/r1.png)

![Page 2](images/r2.png)

![Page 3](images/r3.png)

> This means that root cert can just be used to sign certificates and revocations.

Press ok and the root certificate should be created.

## 2. Create intermediate certificate

Click on `New Certificate`, and fill the fields as shown in the following images:

![Page 1](images/i1.png)

![Page 2](images/i2.png)

![Page 3](images/i3.png)

> *Path length = 0* is optional, it means that no intermediate CA can be issued from this certificate.

![Page 4](images/i4.png)

Press ok and the intermediate certificate should be created.

## 3. Create server certificate

Click on `New Certificate`, and fill the fields as shown in the following images:

![Page 1](images/s1.png)

![Page 2](images/s2.png)

![Page 3](images/s3.png)

![Page 4](images/s4.png)

![Page 5](images/s5.png)

Press ok and the server certificate should be created.


## Place files on the right locations

### For server

Server needs it's private key, certificate and the intermediate CA certificate.
#### Export chain
![[es1.png]]
Place it as `server/certs/chain.crt`.

![[es2.png]]

Place it as  `server/certs/key.pem`.

### For client

The client container needs to have the root certificate.
![[ec1.png]]Place it as `client/certs/root.crt`
