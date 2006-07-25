#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 13;
use File::Spec;
use Net::SSLeay;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::add_ssl_algorithms();

my $key_pem = File::Spec->catfile('t', 'data', 'key.pem.e');
my $key_password = 'secret';
my $cb_1_calls = 0;
my $cb_2_calls = 0;
my $cb_3_calls = 0;

sub callback {
    my ($rwflag, $userdata) = @_;

    $cb_1_calls++;

    is( $$userdata, $key_password, 'recieved userdata properly' );
    return $$userdata;
}

sub callback2 {
    my ($rwflag, $userdata) = @_;

    $cb_2_calls++;

    is( $$userdata, $key_password, 'recieved userdata properly' );
    return $$userdata;
}

sub callback3 {
    my ($rwflag, $userdata) = @_;

    $cb_3_calls++;

    is( $userdata, undef, 'recieved no userdata' );
    return $key_password;
}

my $ctx = Net::SSLeay::CTX_new();
ok($ctx, 'CTX_new');

my $ctx_2 = Net::SSLeay::CTX_new();
ok($ctx, 'CTX_new');

my $ctx_3 = Net::SSLeay::CTX_new();
ok($ctx, 'CTX_new');

Net::SSLeay::CTX_set_default_passwd_cb($ctx, \&callback);
Net::SSLeay::CTX_set_default_passwd_cb_userdata($ctx, \$key_password);

Net::SSLeay::CTX_set_default_passwd_cb($ctx_2, \&callback2);
Net::SSLeay::CTX_set_default_passwd_cb_userdata($ctx_2, \$key_password);

Net::SSLeay::CTX_set_default_passwd_cb($ctx_3, \&callback3);

ok( Net::SSLeay::CTX_use_PrivateKey_file($ctx, $key_pem, &Net::SSLeay::FILETYPE_PEM),
        'CTX_use_PrivateKey_file works with right passphrase and userdata' );

ok( Net::SSLeay::CTX_use_PrivateKey_file($ctx_2, $key_pem, &Net::SSLeay::FILETYPE_PEM),
        'CTX_use_PrivateKey_file works with right passphrase and userdata' );

ok( Net::SSLeay::CTX_use_PrivateKey_file($ctx_3, $key_pem, &Net::SSLeay::FILETYPE_PEM),
        'CTX_use_PrivateKey_file works with right passphrase and without userdata' );

ok( $cb_1_calls == 1
    && $cb_2_calls == 1
    && $cb_3_calls == 1,
    'different cbs per ctx work' );

$key_password = \'incorrect';

ok( !Net::SSLeay::CTX_use_PrivateKey_file($ctx, $key_pem, &Net::SSLeay::FILETYPE_PEM),
        'CTX_use_PrivateKey_file doesn\'t work with wrong passphrase' );

is($cb_1_calls, 2, 'callback called 2 times');
