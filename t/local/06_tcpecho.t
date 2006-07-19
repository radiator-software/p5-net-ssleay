#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 4;
use Socket;
use Symbol qw(gensym);
use Net::SSLeay;

my $sock;
my $pid;

my $port = 1211;
my $msg = 'ssleay-tcp-test';

{
    my $ip = "\x7F\0\0\x01";
    my $serv_params = pack('S n a4 x8', AF_INET, $port, $ip);
    $sock = gensym();
    socket($sock, AF_INET, SOCK_STREAM, 0) or die;
    bind($sock, $serv_params) or die;
    listen($sock, 2) or die;
}

{
    $pid = fork();
    die unless defined $pid;
    if ($pid == 0) {
        my $addr = accept(Net::SSLeay::SSLCAT_S, $sock) or die;

        my $old_out = select(Net::SSLeay::SSLCAT_S);
        $| = 1;
        select($old_out);

        my $got = Net::SSLeay::tcp_read_all();
        is($got, $msg, 'tcp_read_all');

        ok(Net::SSLeay::tcp_write_all(uc($got)), 'tcp_write_all');

        close Net::SSLeay::SSLCAT_S;
        close $sock;

        exit;
    }
}

my @results;
{
    my ($got) = Net::SSLeay::tcpcat('localhost', $port, $msg);
    push @results, [ $got eq uc($msg), 'sent and recieved correctly' ];
}

waitpid $pid, 0;
push @results, [ $? == 0, 'server exited with 0' ];

END {
    Test::More->builder->current_test(2);
    for my $t (@results) {
        ok( $t->[0], $t->[1] );
    }
}
