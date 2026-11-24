# Tests for get_verified_chain

use lib 'inc';

use Net::SSLeay;
use Test::Net::SSLeay qw(can_fork data_file_path initialise_libssl new_ctx tcp_socket);

if (!defined &Net::SSLeay::get_verified_chain) {
    plan skip_all => "No get_verified_chain()";
} elsif (!can_fork()) {
    plan skip_all => "fork() not supported on this system";
} else {
    plan tests => 4;
}

initialise_libssl();

my $ca_file_pem = data_file_path('intermediate-ca.certchain.pem');
my $cert_pem    = data_file_path('simple-cert.cert.pem');
my $key_pem     = data_file_path('simple-cert.key.pem');

sub load_cert {
    my $bio = Net::SSLeay::BIO_new_file(data_file_path("$_[0].cert.pem"), 'r');
    my $x509 = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);
    return $x509;
}

sub subjects {
    return map {
	Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($_))
    } @_;
}

my %subject = map {
    my $x509 = load_cert($_);
    my ($name) = subjects($x509);
    Net::SSLeay::X509_free($x509);
    ($_ => $name);
} qw(simple-cert intermediate-ca root-ca verify-ca);

my $pid;
alarm(30);
END { kill 9,$pid if $pid }

my $server = tcp_socket();
{
    # SSL server - just handle single connect and shutdown connection
    defined($pid = fork()) or BAIL_OUT("failed to fork: $!");
    if ($pid == 0) {
	my $cl = $server->accept();
	my $ctx = new_ctx();
	Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem);
	# Unrelated CA certificate, not part of the trust chain
	Net::SSLeay::CTX_add_extra_chain_cert($ctx, load_cert('verify-ca'));
	my $ssl = Net::SSLeay::new($ctx);
	Net::SSLeay::set_fd($ssl, fileno($cl));
	Net::SSLeay::accept($ssl);
	Net::SSLeay::shutdown($ssl);
	Net::SSLeay::free($ssl);
	Net::SSLeay::CTX_free($ctx);
	close($cl) || die("server close: $!");
	$server->close() || die("server listen socket close: $!");
	exit;
    }
}

my $cl = $server->connect();
my $ctx = new_ctx();
Net::SSLeay::CTX_load_verify_locations($ctx, $ca_file_pem, '');
Net::SSLeay::CTX_set_verify($ctx, Net::SSLeay::VERIFY_PEER());
my $ssl = Net::SSLeay::new($ctx);

my @chain = Net::SSLeay::get_verified_chain($ssl);
is(scalar @chain, 0, 'get_verified_chain is empty before handshake');

Net::SSLeay::set_fd($ssl, $cl);
is(Net::SSLeay::connect($ssl), 1, 'connect');

# Server sends its own and an unrelated certificate, verified chain
# omits the unrelated one and adds the CAs from the trust store
is_deeply([subjects(Net::SSLeay::get_peer_cert_chain($ssl))],
	  [@subject{qw(simple-cert verify-ca)}],
	  'get_peer_cert_chain has peer and unrelated certificate');
is_deeply([subjects(Net::SSLeay::get_verified_chain($ssl))],
	  [@subject{qw(simple-cert intermediate-ca root-ca)}],
	  'get_verified_chain has peer, intermediate and root certificate');

Net::SSLeay::shutdown($ssl);
Net::SSLeay::free($ssl);
Net::SSLeay::CTX_free($ctx);
close($cl) || die("client close: $!");
$server->close() || die("client listen socket close: $!");
waitpid $pid, 0;
