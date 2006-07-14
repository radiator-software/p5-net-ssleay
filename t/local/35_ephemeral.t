#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 3;
use Net::SSLeay;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

ok( my $ctx = Net::SSLeay::CTX_new(), 'CTX_new' );
ok( my $rsa = Net::SSLeay::RSA_generate_key(512, 0x10001), 'RSA_generate_key' ); # 0x10001 = RSA_F4
ok( Net::SSLeay::CTX_set_tmp_rsa($ctx, $rsa), 'CTX_set_tmp_rsa' );
