#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Socket;
use Symbol qw(gensym);
use Net::SSLeay;
use Config;

BEGIN {
  plan skip_all => "fork() not supported on $^O" unless $Config{d_fork};
}

plan tests => 4;

my $sock;
my $pid;

my $port = 1211;
my $msg = 'ssleay-tcp-test';
my $port_trials = 1000;
{
    my $ip = "\x7F\0\0\x01";
    my $serv_params = sockaddr_in($port, $ip);
    $sock = gensym();
    socket($sock, AF_INET, SOCK_STREAM, 0) or die "socket failed: $!";
    # Try to find an available port to bind to
    my $i;
    for ($i = 0; $i < $port_trials; $i++)
    {
	my $serv_params = sockaddr_in($port, $ip);

	last if bind($sock, $serv_params);
	$port++;
    }
    die "Could not find a port to bind to" if $i >= 1000;
    listen($sock, 2) or die "listen failed $!";
}

{
    $pid = fork();
    die  "fork failed: $!" unless defined $pid;
    if ($pid == 0) {
        my $addr = accept(Net::SSLeay::SSLCAT_S, $sock) or die "accept failed $!";

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
    push @results, [ $got eq uc($msg), 'sent and received correctly' ];
}

waitpid $pid, 0;
push @results, [ $? == 0, 'server exited with 0' ];

END {
    Test::More->builder->current_test(2);
    for my $t (@results) {
        ok( $t->[0], $t->[1] );
    }
}
