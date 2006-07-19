#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 8;
use Net::SSLeay;

my %fps = (
        ''                           => 'd41d8cd98f00b204e9800998ecf8427e',
        'a'                          => '0cc175b9c0f1b6a831c399e269772661',
        '38'                         => 'a5771bce93e200c36f7cd9dfd0e5deaa',
        'abc'                        => '900150983cd24fb0d6963f7d28e17f72',
        'message digest'             => 'f96b697d7cb7938d525a2f31aaf161d0',
        'abcdefghijklmnopqrstuvwxyz' => 'c3fcd3d76192e4007dfb496cca67e13b',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij' .
        'klmnopqrstuvwxyz0123456789' => 'd174ab98d277d9f5a5611c2c9f419d9f',
        '123456789012345678901234567890123456789012345678901234' .
        '56789012345678901234567890' => '57edf4a22be3c955ac49da2e2107b67a',
);

for my $data (sort keys %fps) {
    my $hash = Net::SSLeay::MD5($data);
    is(unpack('H32', $hash), $fps{$data}, "MD5 hash for '$data");
}
