#!/usr/bin/perl

use strict;
use Test::More tests => 1;
use Socket;
use Net::SSLeay;

my $sock;
my $pid;

my $port = 1211;

{
	my $ip = "\x7F\0\0\x01";
	my $serv_params = pack('S n a4 x8', AF_INET, $port, $ip);
	socket($sock, AF_INET, SOCK_STREAM, 0);
	bind($sock, $serv_params);
	listen($sock, 2);
}

{
	$pid = fork();
	if ($pid == 0) {
		Net::SSLeay::tcpcat('localhost', $port, 'ssleay-tcp-test');
		exit;
	}
}

{
	my $addr = accept(Net::SSLeay::SSLCAT_S, $sock);

	my $old_out = select(Net::SSLeay::SSLCAT_S);
	$| = 1;
	select $old_out;

	my $got = Net::SSLeay::tcp_read_all();
	kill 2, $pid; #just to be sure.

	is($got, 'ssleay-tcp-test', 'simple tcp message');
}
