#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 7;
use File::Spec;
use Net::SSLeay;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

my $key_pem = File::Spec->catfile('t', 'data', 'key.pem.e');
my $key_password = 'secret';
my $calls = 0;

sub callback {
    my ($rwflag, $userdata) = @_;

    $calls++;

    is( $$userdata, $key_password, 'recieved userdata properly' );
    return $$userdata;
}

my $ctx = Net::SSLeay::CTX_new();
ok($ctx, 'CTX_new');

Net::SSLeay::CTX_set_default_passwd_cb($ctx, \&callback);
Net::SSLeay::CTX_set_default_passwd_cb_userdata($ctx, \$key_password);

ok( Net::SSLeay::CTX_use_PrivateKey_file($ctx, $key_pem, Net::SSLeay::FILETYPE_PEM()),
        'CTX_use_PrivateKey_file works with right passphrase' );

is($calls, 1, 'callback called 1 time');

$key_password = \'incorrect';

ok( !Net::SSLeay::CTX_use_PrivateKey_file($ctx, $key_pem, Net::SSLeay::FILETYPE_PEM()),
        'CTX_use_PrivateKey_file doesn\'t work with wrong passphrase' );

is($calls, 2, 'callback called 2 times');
