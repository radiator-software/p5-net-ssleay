#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 3;
use Net::SSLeay;

my %fps = (
        38	=> 'a5771bce93e200c36f7cd9dfd0e5deaa',
        foo	=> 'acbd18db4cc2f85cedef654fccc4a4d8',
        bar => '37b51d194a7513e45b56f6524f2d51f2'
);

for my $data (sort keys %fps) {
    my $hash = Net::SSLeay::MD5($data);
    is(unpack('H32', $hash), $fps{$data}, "MD5 hash for $data");
}
