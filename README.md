x509ck - Check arbitrary X.509 Certificates
===========================================

I had a problem the other day; I didn't trust that I'd been given
the right CA + certificate + private key combination.  I tried
using `openssl`; then I had two problems.

So I wrote this utility.

Usage is straightforward:

    $ x509ck --ca   suspect-ca.pem \
             --cert suspect-cert.pem \
             --key  suspect-key.pem
    x509 ok!

This checks that:

  1. `suspect-ca.pem` contains a valid, PEM-encoded X.509 cert.
  2. `suspect-cert.pem` contains a valid, PEM-encoded X.509 cert.
  3. `suspect-key.pem` contains a valid, PEM-encoded RSA key.
  4. `suspect-key.pem` is the key for `suspect-cert.pem`
  5. `suspect-ca.pem` signed `suspect-cert.pem`

If you don't have a CA (or don't care about parent signing), you
can omit the `--ca` flag and steps 1 and 5 will be skipped:

    $ x509ck -c suspect-cert.pem \
             -k suspect-key.pem

Happy Hacking!
