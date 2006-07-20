#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 62;
use Socket;
use File::Spec;
use Symbol qw(gensym);
use Net::SSLeay;

my $sock;
my $pid;

my $port = 1212;
my $dest_ip = gethostbyname('localhost');
my $dest_serv_params  = pack ('S n a4 x8', AF_INET, $port, $dest_ip);

my $msg = 'ssleay-test';
my $cert_pem = File::Spec->catfile('t', 'data', 'cert.pem');
my $key_pem = File::Spec->catfile('t', 'data', 'key.pem');

my $cert_name = '/C=PL/ST=Peoples Republic of Perl/L=Net::/O=Net::SSLeay/'
    . 'OU=Net::SSLeay developers/CN=127.0.0.1/emailAddress=rafl@debian.org';

$ENV{RND_SEED} = '1234567890123456789012345678901234567890';

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

{
    my $ip = "\x7F\0\0\x01";
    my $serv_params = pack ('S n a4 x8', AF_INET, $port, $ip);
    $sock = gensym();
    socket($sock, AF_INET, SOCK_STREAM, 0) or die;
    bind($sock, $serv_params) or die;
    listen($sock, 3) or die;


    my $ctx = Net::SSLeay::CTX_new();
    ok($ctx, 'CTX_new');
    ok(Net::SSLeay::CTX_set_cipher_list($ctx, 'ALL'), 'CTX_set_cipher_list');
    ok(Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem), 'set_cert_and_key');

    $pid = fork();
    die unless defined $pid;
    if ($pid == 0) {
        for (1 .. 6) {
            my $ns = gensym();
            my $addr = accept($ns, $sock);

            my $old_out = select($ns);
            $| = 1;
            select($old_out);

            my $ssl = Net::SSLeay::new($ctx);
            ok($ssl, 'new');

            ok(Net::SSLeay::set_fd($ssl, fileno($ns)), 'set_fd using fileno');
            ok(Net::SSLeay::accept($ssl), 'accept');

            ok(Net::SSLeay::get_cipher($ssl), 'get_cipher');

            my $got = Net::SSLeay::ssl_read_all($ssl);
            is($got, $msg, 'ssl_read_all') if $_ < 6;
            ok(Net::SSLeay::ssl_write_all($ssl, uc($got)), 'ssl_write_all');

            Net::SSLeay::free($ssl);
            close $ns;
        }

        Net::SSLeay::CTX_free($ctx);
        close $sock;

        exit;
    }
}

my @results;
{
    my ($got) = Net::SSLeay::sslcat('localhost', $port, $msg);
    push @results, [ $got eq uc($msg), 'send and recieved correctly' ];

}

{
    my $s = gensym();
    socket($s, AF_INET, SOCK_STREAM, 0) or die;
    connect($s, $dest_serv_params) or die;

    {
        my $old_out = select($s);
        $| = 1;
        select($old_out);
    }

    push @results, [ my $ctx = Net::SSLeay::CTX_new(), 'CTX_new' ];
    push @results, [ my $ssl = Net::SSLeay::new($ctx), 'new' ];

    push @results, [ Net::SSLeay::set_fd($ssl, $s), 'set_fd using glob ref' ];
    push @results, [ Net::SSLeay::connect($ssl), 'connect' ];

    push @results, [ Net::SSLeay::get_cipher($ssl), 'get_cipher' ];

    push @results, [ Net::SSLeay::write($ssl, $msg), 'write' ];
    shutdown($s, 1);

    my ($got) = Net::SSLeay::read($ssl);
    push @results, [ $got eq uc($msg), 'read' ];

    Net::SSLeay::free($ssl);
    Net::SSLeay::CTX_free($ctx);

    shutdown($s, 2);
    close $s;

}

{
    my $verify_cb_1_called = 0;
    my $verify_cb_2_called = 0;
    my $verify_cb_3_called = 0;
    {
        my $cert_dir = 't/data';

        my $ctx = Net::SSLeay::CTX_new();
        push @results, [ Net::SSLeay::CTX_load_verify_locations($ctx, '', $cert_dir), 'CTX_load_verify_locations' ];
        Net::SSLeay::CTX_set_verify($ctx, &Net::SSLeay::VERIFY_PEER, \&verify);

        {
            my $s = gensym();
            socket($s, AF_INET, SOCK_STREAM, 0) or die;
            connect($s, $dest_serv_params) or die;
            
            {
                my $old_out = select($s);
                $| = 1;
                select($old_out);
            }

            my $ssl = Net::SSLeay::new($ctx);
            Net::SSLeay::set_fd($ssl, fileno($s));
            Net::SSLeay::connect($ssl);

            Net::SSLeay::write($ssl, $msg);

            shutdown $s, 2;
            close $s;
            Net::SSLeay::free($ssl);

            push @results, [ $verify_cb_1_called == 1, 'verify cb 1 called once' ];
            push @results, [ $verify_cb_2_called == 0, 'verify cb 2 wasn\'t called yet' ];
            push @results, [ $verify_cb_3_called == 0, 'verify cb 3 wasn\'t called yet' ];
        }

        {
            my $s1 = gensym();
            socket($s1, AF_INET, SOCK_STREAM, 0) or die;
            connect($s1, $dest_serv_params) or die;
            
            {
                my $old_out = select($s1);
                $| = 1;
                select($old_out);
            }

            my $s2 = gensym();
            socket($s2, AF_INET, SOCK_STREAM, 0) or die;
            connect($s2, $dest_serv_params) or die;
            
            {
                my $old_out = select($s2);
                $| = 1;
                select($old_out);
            }

            my $ssl1 = Net::SSLeay::new($ctx);
            Net::SSLeay::set_verify($ssl1, &Net::SSLeay::VERIFY_PEER, \&verify2);
            Net::SSLeay::set_fd($ssl1, $s1);

            my $ssl2 = Net::SSLeay::new($ctx);
            Net::SSLeay::set_verify($ssl2, &Net::SSLeay::VERIFY_PEER, \&verify3);
            Net::SSLeay::set_fd($ssl2, $s2);

            Net::SSLeay::connect($ssl1);
            Net::SSLeay::write($ssl1, $msg);
            shutdown $s1, 2;

            Net::SSLeay::connect($ssl2);
            Net::SSLeay::write($ssl2, $msg);
            shutdown $s2, 2;

            close $s1;
            close $s2;

            Net::SSLeay::free($ssl1);
            Net::SSLeay::free($ssl2);

            push @results, [ $verify_cb_1_called == 1, 'verify cb 1 wasn\'t called again' ];
            push @results, [ $verify_cb_2_called == 1, 'verify cb 2 called once' ];
            push @results, [ $verify_cb_3_called == 1, 'verify cb 3 wasn\'t called yet' ];
        }


        Net::SSLeay::CTX_free($ctx);

    }

    sub verify {
        my ($ok, $x509_store_ctx) = @_;
        $verify_cb_1_called++;

        push @results, [ $ok, 'verify cb' ];

        my $cert = Net::SSLeay::X509_STORE_CTX_get_current_cert($x509_store_ctx);
        push @results, [ $cert, 'verify cb cert' ];

        my $issuer  = Net::SSLeay::X509_NAME_oneline(
                Net::SSLeay::X509_get_issuer_name($cert)
        );

        my $subject = Net::SSLeay::X509_NAME_oneline(
                Net::SSLeay::X509_get_subject_name($cert)
        );

        push @results, [ $issuer  eq $cert_name, 'cert issuer'  ];
        push @results, [ $subject eq $cert_name, 'cert subject' ];

        return 1;
    }

    sub verify2 {
        $verify_cb_2_called++;
        return 1;
    }

    sub verify3 {
        $verify_cb_3_called++;
        return 1;
    }
}

{
    my $s = gensym();
    socket($s, AF_INET, SOCK_STREAM, 0) or die;
    connect($s, $dest_serv_params) or die;

    {
        my $old_out = select($s);
        $| = 1;
        select($old_out);
    }

    my $ctx = Net::SSLeay::CTX_new();
    my $ssl = Net::SSLeay::new($ctx);

    Net::SSLeay::set_fd($ssl, fileno($s));
    Net::SSLeay::connect($ssl);

    my $cert = Net::SSLeay::get_peer_certificate($ssl);

    my $subject = Net::SSLeay::X509_NAME_oneline(
            Net::SSLeay::X509_get_subject_name($cert)
    );

    my $issuer  = Net::SSLeay::X509_NAME_oneline(
            Net::SSLeay::X509_get_issuer_name($cert)
    );

    push @results, [ $subject eq $cert_name, 'get_peer_certificate subject' ];
    push @results, [ $issuer  eq $cert_name, 'get_peer_certificate issuer'  ];

    my $data = 'a' x 1024 ** 2;
    my $written = Net::SSLeay::ssl_write_all($ssl, \$data);
    push @results, [ $written == length $data, 'ssl_write_all' ];

    shutdown $s, 1;

    my $got = Net::SSLeay::ssl_read_all($ssl);
    push @results, [ $got eq uc($data), 'ssl_read_all' ];

    Net::SSLeay::free($ssl);
    Net::SSLeay::CTX_free($ctx);

    close $s;
}

waitpid $pid, 0;
push @results, [ $? == 0, 'server exited wiht 0' ];

END {
    Test::More->builder->current_test(38);
    for my $t (@results) {
        ok( $t->[0], $t->[1] );
    }
}
