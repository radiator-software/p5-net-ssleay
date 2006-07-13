#!/usr/bin/perl

use strict;
use Test::More tests => 23;
use Socket;
use IO::Select;
use File::Spec;
use Symbol qw(gensym);
use Net::SSLeay;

my $sock;
my $pid;

my $port = 1212;
my $msg = 'ssleay-test';
my $cert_pem = File::Spec->catfile('t', 'data', 'cert.pem');
my $key_pem = File::Spec->catfile('t', 'data', 'key.pem');

{
    my $ip = "\x7F\0\0\x01";
    my $serv_params = pack ('S n a4 x8', AF_INET, $port, $ip);
    $sock = gensym();
    socket($sock, AF_INET, SOCK_STREAM, 0) or die;
    bind($sock, $serv_params) or die;
    listen($sock, 2) or die;

    Net::SSLeay::load_error_strings();
    Net::SSLeay::SSLeay_add_ssl_algorithms();
    Net::SSLeay::randomize();

    my $ctx = Net::SSLeay::CTX_new();
    ok($ctx, 'CTX_new');
    ok(Net::SSLeay::CTX_set_cipher_list($ctx, 'ALL'), 'CTX_set_cipher_list');
    ok(Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem), 'set_cert_and_key');

    $pid = fork();
    die unless defined $pid;
    if ($pid == 0) {
        for (1 .. 2) {
            my $select = IO::Select->new($sock);
            $select->can_read();

            my $ns = gensym();
            my $addr = accept($ns, $sock);

            my $old_out = select($ns);
            $| = 1;
            select($old_out);

            my $ssl = Net::SSLeay::new($ctx);
            ok($ssl, 'new');

            ok(Net::SSLeay::set_fd($ssl, fileno($ns)), 'set_fd');
            ok(Net::SSLeay::accept($ssl), 'accept');

            ok(Net::SSLeay::get_cipher($ssl), 'get_cipher');

            my $got = Net::SSLeay::ssl_read_all($ssl);
            is($got, $msg, 'ssl_read_all');
            ok(Net::SSLeay::ssl_write_all($ssl, uc($got)), 'ssl_write_all');

            Net::SSLeay::free($ssl);
            close $ns;
            Test::More->builder->current_test(
                Test::More->builder->current_test() + 1
            );
        }

        Net::SSLeay::CTX_free($ctx);
        close $sock;

        exit;
    }
}

{
    my ($got) = Net::SSLeay::sslcat('localhost', $port, $msg);
    Test::More->builder->current_test(9);
    is($got, uc($msg), 'sent and recieved correctly');

}

{
    my @results;

    my $dest_ip = gethostbyname('localhost');
    my $dest_serv_params = sockaddr_in($port, $dest_ip);

    my $s = gensym();
    socket($s, AF_INET, SOCK_STREAM, 0) or die;
    connect($s, $dest_serv_params) or die;

    {
        my $old_out = select($s);
        $| = 1;
        select($old_out);
    }

    my $ctx = Net::SSLeay::CTX_new();
    push @results, [$ctx, 'CTX_new'];
    my $ssl = Net::SSLeay::new($ctx);
    push @results, [$ssl, 'new'];

    push @results, [Net::SSLeay::set_fd($ssl, fileno($s)), 'set_fd'];
    my $res = Net::SSLeay::connect($ssl);
    push @results, [$res, 'connect'];

    push @results, [Net::SSLeay::get_cipher($ssl), 'get_cipher'];

    push @results, [Net::SSLeay::write($ssl, $msg), 'write'];
    shutdown($s, 1);

    my ($got) = Net::SSLeay::read($ssl);

    Net::SSLeay::free($ssl);
    Net::SSLeay::CTX_free($ctx);

    shutdown($s, 2);
    close $s;

    waitpid $pid, 0;

    Test::More->builder->current_test(16);
    is($got, uc($msg), 'read');
    for my $test (@results) {
        ok($test->[0], $test->[1]);
    }
}
