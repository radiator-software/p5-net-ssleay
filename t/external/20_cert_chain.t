#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Socket;
use Net::SSLeay qw( die_if_ssl_error );

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

my @sites = qw( www.verisign.com );

if (@sites) {
    plan tests => scalar @sites * 3;
}
else {
    plan skip_all => 'No external hosts specified for SSL testing';
}

for my $site (@sites) {
    SKIP: {
	my $port = getservbyname  ('https', 'tcp') || 443;
	my $dest_ip = gethostbyname ( $site );

	socket  (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
	connect (S, sockaddr_in($port, $dest_ip) ) or die "connect: $!";
	select  (S); $| = 1; select (STDOUT);

	my $ctx = Net::SSLeay::CTX_new() or die_now("Failed to create SSL_CTX $!");
	my $ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");
	Net::SSLeay::set_fd($ssl, fileno(S));   # Must use fileno
	Net::SSLeay::connect($ssl);
	die_if_ssl_error('bulk: ssl connect');

        my @chain = Net::SSLeay::get_peer_cert_chain($ssl);
        ok(scalar @chain, 'get_peer_cert_chain returns some elements');
	SKIP: {
		if( ! scalar @chain ) {
			skip('check returned no certificate chain!', 2);
		}
		my $x509 = $chain[0];
		ok(my $subject = Net::SSLeay::X509_get_subject_name($x509), "X509_get_subject_name");
		like(Net::SSLeay::X509_NAME_oneline($subject), qr|/OU=.*?/CN=|, "X509_NAME_oneline");
	};
        Net::SSLeay::free($ssl);
        Net::SSLeay::CTX_free($ctx);
    }
}
