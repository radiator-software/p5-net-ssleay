#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Net::SSLeay;

BEGIN {
  plan skip_all => "libressl and OpenSSL 1.1 removed support for ephemeral/temporary RSA private keys" if Net::SSLeay::constant("LIBRESSL_VERSION_NUMBER") || Net::SSLeay::constant("OPENSSL_VERSION_NUMBER") >= 0x10100000;
}

plan tests => 3;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

ok( my $ctx = Net::SSLeay::CTX_new(), 'CTX_new' );
ok( my $rsa = Net::SSLeay::RSA_generate_key(2048, Net::SSLeay::RSA_F4()), 'RSA_generate_key' );
ok( Net::SSLeay::CTX_set_tmp_rsa($ctx, $rsa), 'CTX_set_tmp_rsa' );
