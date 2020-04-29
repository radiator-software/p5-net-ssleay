# Various TLS exporter-related tests

use lib 'inc';

use Net::SSLeay;
use Test::Net::SSLeay qw(tcp_socket);

use Config;
use File::Spec;
use Storable;

if (!$Config{d_fork}) {
    plan skip_all => "fork() not supported on $^O";
} elsif (!defined &Net::SSLeay::export_keying_material) {
    plan skip_all => "No export_keying_material()";
} else {
    plan tests => 36;
}

my $pid;
alarm(30);
END { kill 9,$pid if $pid }

my @rounds = qw(TLSv1 TLSv1.1 TLSv1.2 TLSv1.3);
my (%server_stats, %client_stats);

my ($server_ctx, $client_ctx, $server_ssl, $client_ssl);
Net::SSLeay::initialize();

my $server = tcp_socket();

# Helper for client and server
sub make_ctx
{
    my ($round) = @_;

    my $ctx;
    if ($round =~ /^TLSv1\.3/) {
	return undef unless eval { Net::SSLeay::TLS1_3_VERSION(); };

	# Use API introduced in OpenSSL 1.1.0
	$ctx = Net::SSLeay::CTX_new_with_method(Net::SSLeay::TLS_method());
	Net::SSLeay::CTX_set_min_proto_version($ctx, Net::SSLeay::TLS1_3_VERSION());
	Net::SSLeay::CTX_set_max_proto_version($ctx, Net::SSLeay::TLS1_3_VERSION());
    }
    elsif ($round =~ /^TLSv1\.2/) {
	return undef unless exists &Net::SSLeay::TLSv1_2_method;

	$ctx = Net::SSLeay::CTX_new_with_method(Net::SSLeay::TLSv1_2_method());
    }
    elsif ($round =~ /^TLSv1\.1/) {
	return undef unless exists &Net::SSLeay::TLSv1_1_method;

	$ctx = Net::SSLeay::CTX_new_with_method(Net::SSLeay::TLSv1_1_method());
    }
    else
    {
	$ctx = Net::SSLeay::CTX_new_with_method(Net::SSLeay::TLSv1_method());
    }

    return $ctx;
}

sub server
{
    # SSL server - just handle connections, write, wait for read and repeat
    my $cert_pem = File::Spec->catfile('t', 'data', 'testcert_wildcard.crt.pem');
    my $key_pem = File::Spec->catfile('t', 'data', 'testcert_key_2048.pem');

    defined($pid = fork()) or BAIL_OUT("failed to fork: $!");
    if ($pid == 0) {
	my ($ctx, $ssl, $ret, $cl);

	foreach my $round (@rounds)
	{
	    $cl = $server->accept();

	    $ctx = make_ctx($round);
	    next unless $ctx;

	    Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem);
	    $ssl = Net::SSLeay::new($ctx);
	    Net::SSLeay::set_fd($ssl, fileno($cl));
	    Net::SSLeay::accept($ssl);

	    Net::SSLeay::write($ssl, $round);
	    my $msg = Net::SSLeay::read($ssl);

	    Net::SSLeay::shutdown($ssl);
	    Net::SSLeay::free($ssl);
	}
	exit(0);
    }
}

sub client {
    # SSL client - connect to server, read, test and repeat

    my ($ctx, $ssl, $ret, $cl);
    my $end = "end";

    foreach my $round (@rounds)
    {
	$cl = $server->connect();

	$ctx = make_ctx($round);
	unless($ctx) {
	  SKIP: {
	      skip("Skipping round $round", 9);
	    }
	    next;
	}

	$ssl = Net::SSLeay::new($ctx);
	Net::SSLeay::set_fd($ssl, $cl);
	Net::SSLeay::connect($ssl);
	my $msg = Net::SSLeay::read($ssl);

	test_export($ssl);

	Net::SSLeay::write($ssl, $msg);

	Net::SSLeay::shutdown($ssl);
	Net::SSLeay::free($ssl);
    }

    return;
}

sub test_export
{
    my ($ssl) = @_;

    my ($bytes1_0, $bytes1_1, $bytes1_2, $bytes1_3, $bytes2_0, $bytes2_2_64);

    my $tls_version = Net::SSLeay::get_version($ssl);

    $bytes1_0 = Net::SSLeay::export_keying_material($ssl, 64, 'label 1');
    $bytes1_1 = Net::SSLeay::export_keying_material($ssl, 64, 'label 1', undef);
    $bytes1_2 = Net::SSLeay::export_keying_material($ssl, 64, 'label 1', '');
    $bytes1_3 = Net::SSLeay::export_keying_material($ssl, 64, 'label 1', 'context');
    $bytes2_0 = Net::SSLeay::export_keying_material($ssl, 128, 'label 1', '');
    $bytes2_2_64 = substr($bytes2_0, 0, 64);

    is(length($bytes1_0), 64, "$tls_version: Got enough for bytes1_0");
    is(length($bytes1_1), 64, "$tls_version: Got enough for bytes1_1");
    is(length($bytes1_2), 64, "$tls_version: Got enough for bytes1_2");
    is(length($bytes1_3), 64, "$tls_version: Got enough for bytes1_3");
    is(length($bytes2_0), 128, "$tls_version: Got enough for bytes2_0");

    $bytes1_0 = unpack('H*', $bytes1_0);
    $bytes1_1 = unpack('H*', $bytes1_1);
    $bytes1_2 = unpack('H*', $bytes1_2);
    $bytes1_3 = unpack('H*', $bytes1_3);
    $bytes2_0 = unpack('H*', $bytes2_0);
    $bytes2_2_64 = unpack('H*', $bytes2_2_64);

    # Last argument should default to undef
    is($bytes1_0, $bytes1_1, "$tls_version: context default param is undef");

    # Empty and undefined context are the same for TLSv1.3.
    # Different length export changes the whole values for TLSv1.3.
    if ($tls_version eq 'TLSv1.3') {
	is($bytes1_0, $bytes1_2, "$tls_version: empty and undefined context yields equal values");
	isnt($bytes2_2_64, $bytes1_2, "$tls_version: export length does matter");
    } else {
	isnt($bytes1_0, $bytes1_2, "$tls_version: empty and undefined context yields different values");
	is($bytes2_2_64, $bytes1_2, "$tls_version: export length does not matter");
    }

    isnt($bytes1_3, $bytes1_0, "$tls_version: different context");

    return;
}

# For SSL_export_keying_material_early available with TLSv1.3
sub test_export_early
{

    return;
}

server();
client();
waitpid $pid, 0;
exit(0);
