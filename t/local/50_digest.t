#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Net::SSLeay;

my $have_md2 = exists &Net::SSLeay::MD2;
print "its $have_md2\n";

my %fps = (
        '' => {
            md2 => '8350e5a3e24c153df2275c9f80692773',
            md4 => '31d6cfe0d16ae931b73c59d7e0c089c0',
            md5 => 'd41d8cd98f00b204e9800998ecf8427e',
        },
        'a' => {
            md2 => '32ec01ec4a6dac72c0ab96fb34c0b5d1',
            md4 => 'bde52cb31de33e46245e05fbdbd6fb24',
            md5 => '0cc175b9c0f1b6a831c399e269772661',
        },
        '38' => {
            md2 => '4b85c826321a5ce87db408c908d0709e',
            md4 => 'ae9c7ebfb68ea795483d270f5934b71d',
            md5 => 'a5771bce93e200c36f7cd9dfd0e5deaa',
        },
        'abc' => {
            md2 => 'da853b0d3f88d99b30283a69e6ded6bb',
            md4 => 'a448017aaf21d8525fc10ae87aa6729d',
            md5 => '900150983cd24fb0d6963f7d28e17f72',
        },
        'message digest' => {
            md2 => 'ab4f496bfb2a530b219ff33031fe06b0',
            md4 => 'd9130a8164549fe818874806e1c7014b',
            md5 => 'f96b697d7cb7938d525a2f31aaf161d0',
        },
        'abcdefghijklmnopqrstuvwxyz' => {
            md2 => '4e8ddff3650292ab5a4108c3aa47940b',
            md4 => 'd79e1c308aa5bbcdeea8ed63df412da9',
            md5 => 'c3fcd3d76192e4007dfb496cca67e13b',
        },
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' => {
            md2 => 'da33def2a42df13975352846c30338cd',
            md4 => '043f8582f241db351ce627e153e7f0e4',
            md5 => 'd174ab98d277d9f5a5611c2c9f419d9f',
        },
        '12345678901234567890123456789012345678901234567890123456789012345678901234567890' => {
            md2 => 'd5976f79d83d3a0dc9806c3c66f3efd8',
            md4 => 'e33b4ddc9c38f2199c3e7b164fcc0536',
            md5 => '57edf4a22be3c955ac49da2e2107b67a',
        },
);

plan tests => (keys %fps) * ($have_md2 ? 3 : 2);

for my $data (sort keys %fps) {
    is(unpack('H32', Net::SSLeay::MD2($data)), $fps{$data}->{md2}, "MD2 hash for '$data'")
	if $have_md2;
    is(unpack('H32', Net::SSLeay::MD4($data)), $fps{$data}->{md4}, "MD4 hash for '$data'");
    is(unpack('H32', Net::SSLeay::MD5($data)), $fps{$data}->{md5}, "MD5 hash for '$data'");
}
