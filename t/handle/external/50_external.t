#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Symbol qw(gensym);
use Net::SSLeay::Handle qw(shutdown);

my @sites = qw(
        www.cdw.com
        banking.wellsfargo.com
        perldition.org
        alioth.debian.org
);

plan tests => scalar @sites * 6;

for my $site (@sites) {
    SKIP: {
        my $ssl = gensym();
        eval {
            tie(*$ssl, 'Net::SSLeay::Handle', $site, 443);
        };

        skip('could not connect', 2) if $@;
        pass('connection');

        print $ssl "GET / HTTP/1.0\r\n\r\n";
        my $resp = do { local $/ = undef; <$ssl> };

        like( $resp, qr/^HTTP\/1/, 'response' );
    }
}

{
    my @sock;
    for (my $i = 0; $i < scalar @sites; $i++) {
        SKIP: {
            my $ssl = gensym();
            eval {
                tie(*$ssl, 'Net::SSLeay::Handle', $sites[$i], 443);
            };

            skip('could not connect', 2) if $@;
            pass('connection');

            $sock[$i] = $ssl;
            ok( $ssl, 'got handle' );
        }
    }

    for my $sock (@sock) {
        SKIP : {
            skip('not connected', 2) unless defined $sock;
            pass('connected');

            print $sock "GET / HTTP/1.0\r\n\r\n";

            my $resp = do { local $/ = undef; <$sock> };
            like( $resp, qr/^HTTP\/1/, 'response' );
        }
    }

    close($_) for @sock;
}
