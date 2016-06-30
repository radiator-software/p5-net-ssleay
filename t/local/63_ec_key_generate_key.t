#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Net::SSLeay;

if (!defined &Net::SSLeay::EC_KEY_generate_key) {
    plan skip_all => "no suport for ECC in your OpenSSL";
    exit(0);
}

plan tests => 4;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

my $ec = Net::SSLeay::EC_KEY_generate_key('prime256v1');
ok($ec,'EC key created');

if ($ec) {
    my $key = Net::SSLeay::EVP_PKEY_new();
    my $rv = Net::SSLeay::EVP_PKEY_assign_EC_KEY($key,$ec);
    ok($rv,'EC key assigned to PKEY');

    my $pem = Net::SSLeay::PEM_get_string_PrivateKey($key);
    ok( $pem =~m{^---.* PRIVATE KEY}m, "output key as PEM");

    my $bio = Net::SSLeay::BIO_new( Net::SSLeay::BIO_s_mem());
    Net::SSLeay::BIO_write($bio,$pem);
    my $newkey = Net::SSLeay::PEM_read_bio_PrivateKey($bio);
    ok($newkey,"read key again from PEM");
}
