#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use IO::Socket::INET;
use Net::SSLeay;

plan skip_all => "no OCSP support" 
    if ! defined &Net::SSLeay::OCSP_response_status;

#$Net::SSLeay::trace=3;

my @tests = (
    {
	# this should give us OCSP stapling
	host => 'www.live.com',
	port => 443,
	fingerprint => '10c56ee9e2acaf2e77caeb7072bf6522dd7422b8',
	ocsp_staple => 1,
	expect_status => Net::SSLeay::V_OCSP_CERTSTATUS_GOOD(),
    },
    {
	# no OCSP stapling yet
	host => 'www.google.com',
	port => 443,
	fingerprint => '007a5ab302f14446e2ea24d3a829de22ba1bf950',
	expect_status => Net::SSLeay::V_OCSP_CERTSTATUS_GOOD(),
    },
    {
	# this is revoked
	host => 'revoked.grc.com',
	port => 443,
	fingerprint => '34703c40093461ad3ce087e161c7b7f42abe770c',
	expect_status => Net::SSLeay::V_OCSP_CERTSTATUS_REVOKED(),
    },
);

plan tests => 0+@tests;


my $timeout = 10; # used to TCP connect and SSL connect
my $http_ua = eval { require HTTP::Tiny } && HTTP::Tiny->new(verify_SSL => 0);

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();
my $sha1 = Net::SSLeay::EVP_get_digestbyname('sha1');

TEST:

for my $test (@tests) {
    my $cleanup = __cleanup__->new;
    SKIP: {
	skip 'HTTP::Tiny required but not installed', 1
	    unless $http_ua;

	my $cl = IO::Socket::INET->new(
	    PeerAddr => $test->{host},
	    PeerPort => $test->{port},
	    Timeout => $timeout,
	);
	skip "TCP connect to $test->{host}:$test->{port} failed: $!",1
	    if !$cl;
	diag("tcp connect to $test->{host}:$test->{port} ok");

	my $ctx = Net::SSLeay::CTX_new() or die "failed to create CTX";
	my $ssl = Net::SSLeay::new($ctx) or die "failed to create SSL";

	# enable verification with hopefully usable CAs
	Net::SSLeay::CTX_set_default_verify_paths($ctx);
	Net::SSLeay::CTX_load_verify_locations($ctx,
	    Mozilla::CA::SSL_ca_file(),'')
	    if eval { require Mozilla::CA };
	Net::SSLeay::CTX_set_verify($ctx,Net::SSLeay::VERIFY_PEER(),undef);

	# setup TLS extension and callback to catch stapled OCSP response
	my $stapled_response;
	Net::SSLeay::set_tlsext_status_type($ssl,
	    Net::SSLeay::TLSEXT_STATUSTYPE_ocsp());
	Net::SSLeay::CTX_set_tlsext_status_cb($ctx,sub {
	    my ($ssl,$resp) = @_;
	    diag("got ".($resp ? '':'no ')."stapled OCSP response");
	    return 1 if ! $resp;
	    $stapled_response = Net::SSLeay::i2d_OCSP_RESPONSE($resp);
	    return 1;
	});

	# non-blocking SSL_connect with timeout
	$cl->blocking(0);
	Net::SSLeay::set_fd($ssl,fileno($cl));
	my $end = time() + $timeout;
	my $rv;
	while (($rv = Net::SSLeay::connect($ssl)) < 0) {
	    my $to = $end-time();
	    $to<=0 and last;
	    my $err = Net::SSLeay::get_error($ssl,$rv);
	    vec( my $vec = '',fileno($cl),1) = 1;
	    if ( $err == Net::SSLeay::ERROR_WANT_READ()) {
		select($vec,undef,undef,$to);
	    } elsif ( $err == Net::SSLeay::ERROR_WANT_WRITE()) {
		select(undef,$vec,undef,$to);
	    }
	}
	skip "SSL_connect with $test->{host}:$test->{port} failed: ".
	    Net::SSLeay::print_errs(''),1
	    if $rv<=0;
	diag("SSL_connect ok");

	# make sure we talk to the right party, e.g. no SSL interception
	my $leaf_cert = Net::SSLeay::get_peer_certificate($ssl);
	$cleanup->add(sub { Net::SSLeay::X509_free($leaf_cert) }) if $leaf_cert;
	my $fp = $leaf_cert
	    && unpack("H*",Net::SSLeay::X509_digest($leaf_cert,$sha1));
	skip "could not get fingerprint",1 if !$fp;
	skip "bad fingerprint $fp for $test->{host}:$test->{port}",1
	    if $fp ne $test->{fingerprint};
	diag("fingerprint matches");

	if ( $test->{ocsp_staple} && ! $stapled_response ) {
	    fail("did not get expected stapled OCSP response on $test->{host}:$test->{port}");
	    next TEST;
	}

	# create OCSP_REQUEST for all certs
	my @requests;
	for my $cert (Net::SSLeay::get_peer_cert_chain($ssl)) {
	    my $subj = Net::SSLeay::X509_NAME_oneline(
		Net::SSLeay::X509_get_subject_name($cert));
	    my $uri = Net::SSLeay::P_X509_get_ocsp_uri($cert);
	    if (!$uri) {
		diag("no OCSP URI for cert $subj");
		next;
	    }
	    my $id = eval { Net::SSLeay::OCSP_cert2ids($ssl,$cert) } or do {
		fail("failed to get OCSP_CERTIDs for cert $subj: $@");
		next TEST;
	    };
	    my $req = Net::SSLeay::OCSP_ids2req($id);
	    push @requests, [ $uri,$req,$id,$subj ];
	    $cleanup->add(sub { Net::SSLeay::OCSP_REQUEST_free($req) });
	}
	if (!@requests) {
	    fail("no certificate checks for $test->{host}:$test->{port}");
	    next TEST;
	}

	my $check_response = sub {
	    my ($resp,$req,$id,$expect_status) = @_;
	    if ( Net::SSLeay::OCSP_response_status($resp)
		!= Net::SSLeay::OCSP_RESPONSE_STATUS_SUCCESSFUL()) {
		return [ undef,"response bad status ".
		    Net::SSLeay::OCSP_response_status_str(Net::SSLeay::OCSP_response_status($resp)) ];
	    } elsif ( ! eval {
		Net::SSLeay::OCSP_response_verify($ssl,$resp,$req) }) {
		return [ undef,"cannot verify response: $@" ];
	    }
	    # extract result for id
	    my ($status) = Net::SSLeay::OCSP_response_results($resp,$id);
	    return [ undef,"no data for cert in response: $status->[1]" ]
		if ! $status->[2];
	    if ($expect_status != $status->[2]{statusType}) {
		return [ undef,
		    "unexpected status=$status->[2]{statusType} (expected $expect_status): $status->[1]" ]
	    } elsif ( $status->[2]{nextUpdate} ) {
		diag("status=$expect_status as expected: nextUpd=".localtime($status->[2]{nextUpdate}));
	    } else {
		diag("status=$expect_status as expected: no nextUpd");
	    }
	    return $status;
	};

	if ($stapled_response) {
	    my $stat = $check_response->(
		Net::SSLeay::d2i_OCSP_RESPONSE($stapled_response),
		undef, # no OCSP_REQUEST
		$requests[0][2], # stapled response is for the leaf certificate
		$test->{expect_status}
	    );
	    if (!$stat->[0]) {
		fail($stat->[1]);
		next TEST;
	    }
	}

	for(my $i=0;$i<@requests;$i++) {
	    my ($uri,$req,$id,$subj) = @{$requests[$i]};
	    if ( ! $http_ua ) {
		diag("no HTTP: skip checking $uri | $subj");
		next
	    }
	    my $res = $http_ua->request('POST',$uri, {
		headers => { 'Content-type' => 'application/ocsp-request' },
		content => Net::SSLeay::i2d_OCSP_REQUEST($req),
		timeout => $timeout,
	    });
	    if (!$res->{success}) {
		if ($res->{status} == 599) {
		    # internal error, assume network problem
		    diag("disabling HTTP because of $http_ua->{reason}");
		    $http_ua = undef;
		}
		diag("$http_ua->{reason}: skip checking $uri | $subj");
		next;
	    }
	    my $resp = eval { Net::SSLeay::d2i_OCSP_RESPONSE($res->{content}) };
	    if (!$resp) {
		diag("bad OCSP response($@): skip checking $uri | $subj");
		next;
	    }
	    my $stat = $check_response->(
		$resp,
		$req,
		$id,
		($i>0) ? Net::SSLeay::V_OCSP_CERTSTATUS_GOOD() : $test->{expect_status},
	    );
	    if (!$stat->[0]) {
		fail($stat->[1]);
		next TEST;
	    }
	}

	pass("OCSP test $test->{host}:$test->{port} ok");
    }
}

{
    # cleanup stuff when going out of scope
    package __cleanup__;
    sub new { bless [],shift };
    sub add { my $self = shift; push @$self,@_ }
    sub DESTROY {
	my $self = shift;
	&$_ for(@$self)
    }
}
