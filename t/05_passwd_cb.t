#!/usr/bin/perl

use strict;
use Test::More tests => 5;
use File::Spec;
use Net::SSLeay;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

my $key_pem = File::Spec->catfile('t', 'data', 'key.pem.e');
my $key_password = 'secret';
my $calls = 0;

sub callback {
    $calls++;
    return $key_password;
}

my $ctx = Net::SSLeay::CTX_new();
ok($ctx, 'CTX_new');

Net::SSLeay::CTX_set_default_passwd_cb($ctx, \&callback);

ok( Net::SSLeay::CTX_use_PrivateKey_file($ctx, $key_pem, Net::SSLeay::FILETYPE_PEM()),
        'CTX_use_PrivateKey_file works with right passphrase' );

is($calls, 1, 'callback called 1 time');

$key_password = 'incorrect';

ok( !Net::SSLeay::CTX_use_PrivateKey_file($ctx, $key_pem, Net::SSLeay::FILETYPE_PEM()),
        'CTX_use_PrivateKey_file doesn\'t work with wrong passphrase' );

is($calls, 2, 'callback called 2 times');
