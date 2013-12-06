#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Socket;
use File::Spec;
use Symbol qw(gensym);
use Net::SSLeay;
use Config;

BEGIN {
  plan skip_all => "openssl 1.0.2 required" unless Net::SSLeay::SSLeay >= 0x10002000;
  plan skip_all => "fork() not supported on $^O" unless $Config{d_fork};
}

plan tests => 6; 

my $sock;
my $pid;

my $port = 40000+int(rand(9999));
my $ip = "\x7F\0\0\x01";
my $serv_params  = sockaddr_in($port, $ip);

my $msg = 'ssleay-alpn-test';
my $cert_pem = File::Spec->catfile('t', 'data', 'cert.pem');
my $key_pem = File::Spec->catfile('t', 'data', 'key.pem');
my @results;
Net::SSLeay::initialize();

{
    # SSL server
    $sock = gensym();
    socket($sock, AF_INET, SOCK_STREAM, 0) or BAIL_OUT("failed to open socket: $!");
    bind($sock, $serv_params) or BAIL_OUT("failed to bind socket: $!");
    listen($sock, 3) or BAIL_OUT("failed to listen on socket: $!");

    $pid = fork();
    BAIL_OUT("failed to fork: $!") unless defined $pid;
    if ($pid == 0) {
        my $ns = gensym();
        my $addr = accept($ns, $sock);
        my $old_out = select($ns);
        $| = 1;
        select($old_out);

        my $ctx = Net::SSLeay::CTX_tlsv1_new();
        Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem);

        my $rv = Net::SSLeay::CTX_set_alpn_select_cb($ctx, ['http/1.1','spdy/2']);
        is($rv, 1, 'CTX_set_alpn_select_cb');

        my $ssl = Net::SSLeay::new($ctx);
        Net::SSLeay::set_fd($ssl, fileno($ns));
        Net::SSLeay::accept($ssl);

        is(Net::SSLeay::P_alpn_selected($ssl), 'spdy/2', 'P_alpn_selected/server');

        my $got = Net::SSLeay::ssl_read_all($ssl);
        is($got, $msg, 'ssl_read_all compare');

        Net::SSLeay::ssl_write_all($ssl, uc($got));
        Net::SSLeay::free($ssl);
        Net::SSLeay::CTX_free($ctx);
        close $ns;
        close $sock;
        exit;
    }
}

{
    # SSL client
    my $s1 = gensym();
    socket($s1, AF_INET, SOCK_STREAM, 0) or BAIL_OUT("failed to open socket: $!");
    connect($s1, $serv_params) or BAIL_OUT("failed to connect: $!");
    my $old_out = select($s1);
    $| = 1;
    select($old_out);

    my $ctx1 = Net::SSLeay::CTX_tlsv1_new();

    my $rv = Net::SSLeay::CTX_set_alpn_protos($ctx1, ['spdy/2','http/1.1']);
    push @results, [ $rv==0, 'CTX_set_alpn_protos'];

    Net::SSLeay::CTX_set_options($ctx1, &Net::SSLeay::OP_ALL);
    my $ssl1 = Net::SSLeay::new($ctx1);
    Net::SSLeay::set_fd($ssl1, $s1);
    Net::SSLeay::connect($ssl1);
    Net::SSLeay::ssl_write_all($ssl1, $msg);

    push @results, [ 'spdy/2' eq Net::SSLeay::P_alpn_selected($ssl1), 'P_alpn_selected/client'];

    Net::SSLeay::free($ssl1);
    Net::SSLeay::CTX_free($ctx1);
    close $s1;
}

waitpid $pid, 0;
push @results, [$? == 0, 'server exited with 0'];
END {
  Test::More->builder->current_test(3);
  ok( $_->[0], $_->[1] ) for (@results);
}
