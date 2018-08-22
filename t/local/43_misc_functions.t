#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Socket;
use File::Spec;
use Net::SSLeay;
use Config;
use IO::Socket::INET;

BEGIN {
  plan skip_all => "fork() not supported on $^O" unless $Config{d_fork};
}

my $tests = 20;
plan tests => $tests;

my $pid;
alarm(30);
END { kill 9,$pid if $pid }

# Values that were previously looked up for get_keyblock_size test
# Revisit: currently the only known user for get_keyblock_size is
# EAP-FAST. How it works with AEAD ciphers is for future study.
our %non_aead_cipher_to_keyblock_size =
    (
     'RC4-MD5' => 64,
     'RC4-SHA' => 72,
     'AES256-SHA256' => 160,
     'AES128-SHA256' => 128,
     'AES128-SHA' => 104,
     'AES256-SHA' => 136,
    );

our %aead_cipher_to_keyblock_size =
    (
     'AES128-GCM-SHA256' => 56,
     'AES256-GCM-SHA384' => 88,

     # Only in TLS 1.3
     'TLS_AES_128_GCM_SHA256' => 56,
     'TLS_AES_256_GCM_SHA384' => 88,
     'TLS_CHACHA20_POLY1305_SHA256' => 88,
    );

# Combine the two hahes
our %cipher_to_keyblock_size = (%non_aead_cipher_to_keyblock_size, %aead_cipher_to_keyblock_size);

my $server;
Net::SSLeay::initialize();

{
    # SSL server - just handle single connect, send information to
    # client and exit

    my $cert_pem = File::Spec->catfile('t', 'data', 'cert.pem');
    my $key_pem = File::Spec->catfile('t', 'data', 'key.pem');

    $server = IO::Socket::INET->new( LocalAddr => '127.0.0.1', Listen => 3)
	or BAIL_OUT("failed to create server socket: $!");

    defined($pid = fork()) or BAIL_OUT("failed to fork: $!");
    if ($pid == 0) {
	my $cl = $server->accept or BAIL_OUT("accept failed: $!");
	my $ctx = Net::SSLeay::CTX_new();
	Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem);
#	my $get_keyblock_size_ciphers = join(':', keys(%cipher_to_keyblock_size));
	my $get_keyblock_size_ciphers = join(':', keys(%non_aead_cipher_to_keyblock_size));
	Net::SSLeay::CTX_set_cipher_list($ctx, $get_keyblock_size_ciphers);
	my $ssl = Net::SSLeay::new($ctx);

	Net::SSLeay::set_fd($ssl, fileno($cl));
	Net::SSLeay::accept($ssl);

	# Send our idea of Finished messages to the client.
	my ($f_len, $finished_s, $finished_c);

	$f_len = Net::SSLeay::get_finished($ssl, $finished_s);
	Net::SSLeay::write($ssl, "server: $f_len ". unpack('H*', $finished_s));

	$f_len = Net::SSLeay::get_peer_finished($ssl, $finished_c);
	Net::SSLeay::write($ssl, "client: $f_len ". unpack('H*', $finished_c));

	# Echo back the termination request from client
	my $end = Net::SSLeay::read($ssl);
	Net::SSLeay::write($ssl, $end);
	exit(0);
    }
}

sub client {
    # SSL client - connect to server and receive information that we
    # compare to our expected values

    my ($f_len, $f_len_trunc, $finished_s, $finished_c, $msg, $expected);

    my $saddr = $server->sockhost.':'.$server->sockport;
    my $cl = IO::Socket::INET->new($saddr)
	or BAIL_OUT("failed to connect to server: $!");
    my $ctx = Net::SSLeay::CTX_new();
    Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL);
    my $ssl = Net::SSLeay::new($ctx);

    Net::SSLeay::set_fd($ssl, $cl);

    client_test_finished($ssl);
    client_test_keyblock_size($ssl);

    # Tell the server to quit and see that our connection is still up
    my $end = "end";
    Net::SSLeay::write($ssl, $end);
    ok($end eq Net::SSLeay::read($ssl),  'Successful termination');
    return;
}

client();
waitpid $pid, 0;
exit(0);

# Test get_finished() and get_peer_finished() with server.
sub client_test_finished
{
    my ($ssl) = @_;
    my ($f_len, $f_len_trunc, $finished_s, $finished_c, $msg, $expected);

    # Finished messages have not been sent yet
    $f_len = Net::SSLeay::get_peer_finished($ssl, $finished_s);
    ok($f_len == 0, 'Return value for get_peer_finished is empty before connect for server');
    ok(defined $finished_s && $finished_s eq '', 'Server Finished is empty');

    $f_len = Net::SSLeay::get_finished($ssl, $finished_c);
    ok($f_len == 0, 'Finished is empty before connect for client');
    ok(defined $finished_c && $finished_c eq '', 'Client Finished is empty');

    # Complete connection. After this we have Finished messages from both peers.
    Net::SSLeay::connect($ssl);

    $f_len = Net::SSLeay::get_peer_finished($ssl, $finished_s);
    ok($f_len, 'Server Finished is not empty');
    ok($f_len == length($finished_s), 'Return value for get_peer_finished equals to Finished length');
    $expected = "server: $f_len " . unpack('H*', $finished_s);
    $msg = Net::SSLeay::read($ssl);
    ok($msg eq $expected, 'Server Finished is equal');

    $f_len = Net::SSLeay::get_finished($ssl, $finished_c);
    ok($f_len, 'Client Finished is not empty');
    ok($f_len == length($finished_c), 'Return value for get_finished equals to Finished length');
    $expected = "client: $f_len " . unpack('H*', $finished_c);
    $msg = Net::SSLeay::read($ssl);
    ok($msg eq $expected, 'Client Finished is equal');

    ok($finished_s ne $finished_c, 'Server and Client Finished are not equal');

    # Finished should still be the same. See that we can fetch truncated values.
    my $trunc8_s = substr($finished_s, 0, 8);
    $f_len_trunc = Net::SSLeay::get_peer_finished($ssl, $finished_s, 8);
    ok($f_len_trunc == $f_len, 'Return value for get_peer_finished is unchanged when count is set');
    ok($trunc8_s eq $finished_s, 'Count works for get_peer_finished');

    my $trunc8_c = substr($finished_c, 0, 8);
    $f_len_trunc = Net::SSLeay::get_finished($ssl, $finished_c, 8);
    ok($f_len_trunc == $f_len, 'Return value for get_finished is unchanged when count is set');
    ok($trunc8_c eq $finished_c, 'Count works for get_finished');

}

# Test get_keyblock_size
# Notes: With TLS 1.3 the cipher is always an AEAD cipher. If AEAD
# ciphers are enabled for TLS 1.2 and earlier, with LibreSSL
# get_keyblock_size returns -1 when AEAD cipher is chosen.
sub client_test_keyblock_size
{
    my ($ssl) = @_;

    my $cipher = Net::SSLeay::get_cipher($ssl);
    ok($cipher, "get_cipher returns a value: $cipher");

    my $keyblock_size = &Net::SSLeay::get_keyblock_size($ssl);
    ok(defined $keyblock_size, 'get_keyblock_size return value is defined');
    if ($keyblock_size == -1)
    {
	# Accept -1 with AEAD ciphers with LibreSSL
	like(Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_VERSION()), qr/^LibreSSL/, 'get_keyblock_size returns -1 with LibreSSL');
	ok(defined $aead_cipher_to_keyblock_size{$cipher}, 'keyblock size is -1 for an AEAD cipher');
    }
    else
    {
	ok($keyblock_size >= 0, 'get_keyblock_size return value is not negative');
	ok($cipher_to_keyblock_size{$cipher} == $keyblock_size, "keyblock size $keyblock_size is the expected value $cipher_to_keyblock_size{$cipher}");
    }
}
