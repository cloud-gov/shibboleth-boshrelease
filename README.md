# [WIP] BOSH Release for shibboleth

This is a WIP identity provider suitable for use as a SAML provider in CloudFoundry.

## Configuring the idp tomcat instance

By default tomcat is configured to use SSL with a self-signed certificate and will be started on port 8443.

### Using your own certificate

Add the following properties to a file called `my-secrets.yml`:

- `properties.idp.sslCertificate`: Specifies your SSL certificate

- `idp.sslPrivateKey`: Specifies your private key.  The key must be a passphrase-less key.


``` yaml
---
properties:
  idp:
    sslCertificate: |
        -----BEGIN CERTIFICATE-----
        YOUR CERT HERE
        -----END CERTIFICATE-----
    sslPrivateKey: |
        -----BEGIN RSA PRIVATE KEY-----
        YOUR KEY HERE
        -----END RSA PRIVATE KEY-----
```

You now suffix this file path to the `make_manifest` command:

```
templates/make_manifest warden my-secrets.yml
bosh -n deploy
```

### Generating a self-signed certificate

1. Generate your private key with any passphrase

`openssl genrsa -aes256 -out server.key 1024`

2. Remove passphrase from key

`openssl rsa -in server.key -out server.key`

3. Generate certificate signing request for CA

`openssl req -x509 -sha256 -new -key server.key -out server.csr`

4. Generate self-signed certificate with 365 days expiry-time

`openssl x509 -sha256 -days 365 -in server.csr -signkey server.key -out selfsigned.crt`

### Notes

- The property `idp.port` can't be set to `8989` because this port is used by BOSH to monitor the server.

## Using the UAA database with shibboleth for authentication
*TODO*

## Usage

To use this bosh release, first upload it to your bosh:

```
bosh target BOSH_HOST
git clone https://github.com/cloudfoundry-community/shibboleth-boshrelease.git
cd shibboleth-boshrelease
bosh upload release releases/shibboleth/shibboleth-1.yml
```

For [bosh-lite](https://github.com/cloudfoundry/bosh-lite), you can quickly create a deployment manifest & deploy a cluster. Note that this requires that you have installed [spruce](https://github.com/geofffranks/spruce).

```
templates/make_manifest warden
bosh -n deploy
```

For AWS EC2, create a single VM:

```
templates/make_manifest aws-ec2
bosh -n deploy
```

### Override security groups

For AWS & Openstack, the default deployment assumes there is a `default` security group. If you wish to use a different security group(s) then you can pass in additional configuration when running `make_manifest` above.

Create a file `my-networking.yml`:

``` yaml
---
networks:
  - name: shibboleth1
    type: dynamic
    cloud_properties:
      security_groups:
        - shibboleth
```

Where `- shibboleth` means you wish to use an existing security group called `shibboleth`.

You now suffix this file path to the `make_manifest` command:

```
templates/make_manifest openstack-nova my-networking.yml
bosh -n deploy
```

### Development

As a developer of this release, create new releases and upload them:

```
bosh create release --force && bosh -n upload release
```

### Final releases

To share final releases:

```
bosh create release --final
```

By default the version number will be bumped to the next major number. You can specify alternate versions:


```
bosh create release --final --version 2.1
```
