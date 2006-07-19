#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 45;
use Socket;
use File::Spec;
use IO::Handle;
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
        for (1 .. 4) {
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
            is($got, $msg, 'ssl_read_all') if $_ < 4;
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

    use Data::Dumper;
    diag Dumper($s);

    my $s_handle = IO::Handle->new_from_fd( fileno($s), 'r+' );

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
    my $verify_cb_called = 0;
    {
        my $cert_dir = 't/data';

        my $s = gensym();
        socket($s, AF_INET, SOCK_STREAM, 0) or die;
        connect($s, $dest_serv_params) or die;
        
        {
            my $old_out = select($s);
            $| = 1;
            select($old_out);
        }

        my $ctx = Net::SSLeay::CTX_new();
        push @results, [ Net::SSLeay::CTX_load_verify_locations($ctx, '', $cert_dir), 'CTX_load_verify_locations' ];
        Net::SSLeay::CTX_set_verify($ctx, &Net::SSLeay::VERIFY_PEER, \&verify);

        my $ssl = Net::SSLeay::new($ctx);
        Net::SSLeay::set_fd($ssl, fileno($s));
        Net::SSLeay::connect($ssl);

        Net::SSLeay::write($ssl, $msg);

        Net::SSLeay::free($ssl);
        Net::SSLeay::CTX_free($ctx);
        shutdown $s, 2;
        close $s;

        push @results, [ $verify_cb_called == 1, 'verify cb called once' ];
    }

    sub verify {
        my ($ok, $x509_store_ctx) = @_;
        $verify_cb_called++;

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
    Test::More->builder->current_test(26);
    for my $t (@results) {
        ok( $t->[0], $t->[1] );
    }
}
