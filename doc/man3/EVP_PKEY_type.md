=pod

=head1 NAME

EVP_PKEY_type,
EVP_PKEY_id,
EVP_PKEY_base_id,
EVP_PKEY_set_type,
EVP_PKEY_set_type_str,
EVP_PKEY_set_alias_type,
- examine and manipulate type of public key

=head1 SYNOPSIS

 #include <openssl/evp.h>

 int EVP_PKEY_type(int type);
 int EVP_PKEY_id(const EVP_PKEY *pkey);
 int EVP_PKEY_base_id(const EVP_PKEY *pkey);
 int EVP_PKEY_set_type(EVP_PKEY *pkey, int type);
 int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len);
 int EVP_PKEY_set_alias_type(EVP_PKEY *pkey, int type);

=head1 DESCRIPTION

EVP_PKEY_set_alias_type() allows modifying a EVP_PKEY to use a
different set of algorithms than the default. This is currently used
to support SM2 keys, which use an identical encoding to ECDSA.

=head1 RETURN VALUES

EVP_PKEY_set_alias_type() returns 1 on success and 0 on error.

=head1 COPYRIGHT

Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.

Licensed under the OpenSSL license (the "License").  You may not use
this file except in compliance with the License.  You can obtain a copy
in the file LICENSE in the source distribution or at
L<https://www.openssl.org/source/license.html>.

=cut
