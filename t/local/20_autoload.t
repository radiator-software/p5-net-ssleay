#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 6;
use Net::SSLeay;

eval "use Test::Exception;";
plan skip_all => 'Some tests need Test::Exception' if $@;

{
    my $const;
    lives_ok(sub {
            $const = Net::SSLeay::OP_NO_TLSv1();
    }, 'some random constant exists');

    ok( defined $const, '  and has a defined value' );
}

lives_ok(sub {
        Net::SSLeay::make_form( foo => 'bar' );
}, 'some random function gets autoloaded');


throws_ok(sub {
        Net::SSLeay::TXT_RC2_128_CBC_EXPORT40_WITH_MD5();
}, qr/^Can't locate .*?TXT_RC2_128\.al/, 'disabled constant doesn\'t exist');

throws_ok(sub {
        Net::SSLeay::123x();
}, qr/^Can't locate .*?123x\.al/, 'invalid constant doesn\'t exist' );

throws_ok(sub {
        Net::SSLeay::_TEST_INVALID_CONSTANT();
}, qr/^Your vendor has not defined SSLeay macro _TEST_INVALID_CONSTANT /,
'raises an appropriate error when an openssl macro isn\'t defined');
