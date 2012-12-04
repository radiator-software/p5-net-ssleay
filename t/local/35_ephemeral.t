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
ok( my $rsa = Net::SSLeay::RSA_generate_key(2048, Net::SSLeay::RSA_F4()), 'RSA_generate_key' );
ok( Net::SSLeay::CTX_set_tmp_rsa($ctx, $rsa), 'CTX_set_tmp_rsa' );
