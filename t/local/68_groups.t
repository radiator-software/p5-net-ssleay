use lib 'inc';

use Net::SSLeay;
use Test::Net::SSLeay qw( data_file_path initialise_libssl );

initialise_libssl();

if (!defined &Net::SSLeay::get1_groups) {
    plan skip_all => "no support for group functions";
} else {
    plan tests => 8;
}

# for debugging only
my $DEBUG = 0;

my $version_num = Net::SSLeay::OPENSSL_VERSION_NUMBER();

my $client = _minSSL->new();
my $server = _minSSL->new( cert => [
    data_file_path('simple-cert.cert.pem'),
    data_file_path('simple-cert.key.pem'),
]);

SKIP: {
    skip "No support for get_negotiated_group() and group_to_name() in " . Net::SSLeay::SSLeay_version(), 3
        if $version_num < 0x30000000;

    # Basic handshake with groups and get negotiated group
    ok(_handshake_and_check($client, $server, 'P-521:P-384', 'P-521', 'P-521'), 'handshake with P-521 and check negotiated group');
    ok(_handshake_and_check($client, $server, 'P-521:P-384', 'P-384', 'P-384'), 'handshake with P-384 and check negotiated group');

    # Test with single matching group
    ok(_handshake_and_check($client, $server, 'P-256', 'P-256', 'P-256'), 'handshake with single matching group');
}

# Test SSL_get_shared_group
my ($total_count, $shared0, $shared1) = _handshake_and_get_shared($client, $server, 'P-521:P-384', 'P-384:P-521');
is($total_count, 2, 'get_shared_group(-1) returns count of shared groups');
ok(defined($shared0) && $shared0 > 0, 'get_shared_group(0) returns valid group');
ok(defined($shared1) && $shared1 > 0, 'get_shared_group(1) returns valid group');

SKIP: {
    skip "No support for get_negotiated_group() in " . Net::SSLeay::SSLeay_version(), 1
        if $version_num < 0x30000000;

    # Test negotiated group before handshake
    $client->state_connect('P-521');
    my $neg_before = Net::SSLeay::get_negotiated_group($client->_ssl());
    ok($neg_before == 0, 'negotiated group is 0 before handshake');
}

# Test get1_groups - returns client groups on server side after ClientHello
$client->state_connect('P-521:P-384');
$server->state_accept('P-521:P-384');
_do_handshake($client, $server);
my $groups = Net::SSLeay::get1_groups($server->_ssl());
is(@{$groups}, 2, 'get1_groups returns two groups');

sub _handshake_and_get_shared {
    my ($client, $server, $server_group, $client_group) = @_;
    $client->state_connect($client_group);
    $server->state_accept($server_group);

    _do_handshake($client, $server);

    # get_shared_group must be called on server side
    my $total_count = Net::SSLeay::get_shared_group($server->_ssl(), -1);
    my $shared0 = Net::SSLeay::get_shared_group($server->_ssl(), 0);
    my $shared1 = Net::SSLeay::get_shared_group($server->_ssl(), 1);

    return ($total_count, $shared0, $shared1);
}

sub _handshake_and_check {
    my ($client, $server, $server_group, $client_group, $expected_group) = @_;
    $client->state_connect($client_group);
    $server->state_accept($server_group);

    # Test negotiated group before handshake
    my $neg_before = Net::SSLeay::get_negotiated_group($client->_ssl());
    return 0 if $neg_before != 0;

    my $result = _do_handshake($client, $server);
    return 0 unless $result;

    my $negotiated = Net::SSLeay::get_negotiated_group($client->_ssl());
    my $negotiated_name = Net::SSLeay::group_to_name($client->_ssl(), $negotiated);

    # Convert expected group name to NID and name for comparison
    my $exp_nid_and_name = _group_name_to_nid_and_name($expected_group);

    $DEBUG && warn "Expected: $expected_group (NID: $exp_nid_and_name->[0], Name: $exp_nid_and_name->[1]), Got: $negotiated\n";

    return $negotiated == $exp_nid_and_name->[0] && $negotiated_name eq $exp_nid_and_name->[1];
}

sub _do_handshake {
    my ($client, $server) = @_;

    my ($client_done, $server_done);
    for(my $tries = 0; $tries < 10 and !$client_done || !$server_done; $tries++) {
        $client_done ||= $client->handshake || 0;
        $server_done ||= $server->handshake || 0;

        my $transfer = 0;
        if (defined(my $data = $client->bio_read())) {
            $DEBUG && warn "client -> server: ".length($data)." bytes\n";
            $server->bio_write($data);
            $transfer++;
        }
        if (defined(my $data = $server->bio_read())) {
            $DEBUG && warn "server -> client: ".length($data)." bytes\n";
            $client->bio_write($data);
            $transfer++;
        }
        if (!$transfer) {
            $client_done = $server_done = 1;
        }
    }

    return $client_done && $server_done;
}

sub _group_name_to_nid_and_name {
    my $name = shift;
    # Common group name to NID mappings
    my %groups = (
        'P-256' => [415, 'secp256r1'],
        'P-384' => [715, 'secp384r1'],
        'P-521' => [716, 'secp521r1'],
    );
    return $groups{$name} || 0;
}


{
    package _minSSL;

    use Test::Net::SSLeay qw(new_ctx);

    sub new {
        my ($class,%args) = @_;
        my $ctx = new_ctx();
        Net::SSLeay::CTX_set_options($ctx,Net::SSLeay::OP_ALL());
        Net::SSLeay::CTX_set_cipher_list($ctx,'ECDHE');
        Net::SSLeay::CTX_set_ecdh_auto($ctx,1)
            if defined &Net::SSLeay::CTX_set_ecdh_auto;
        my $id = 'client';
        if ($args{cert}) {
            my ($cert,$key) = @{ delete $args{cert} };
            Net::SSLeay::set_cert_and_key($ctx, $cert, $key)
                || die "failed to use cert file $cert,$key";
            $id = 'server';
        }

        my $self = bless { id => $id, ctx => $ctx }, $class;
        return $self;
    }

    sub state_accept {
        my ($self,$group) = @_;
        _reset($self,$group);
        Net::SSLeay::set_accept_state($self->{ssl});
    }

    sub state_connect {
        my ($self,$group) = @_;
        _reset($self,$group);
        Net::SSLeay::set_connect_state($self->{ssl});
    }

    sub handshake {
        my $self = shift;
        my $rv = Net::SSLeay::do_handshake($self->{ssl});
        $rv = _error($self,$rv);
        return $rv;
    }

    sub bio_write {
        my ($self,$data) = @_;
        defined $data and $data ne '' or return;
        Net::SSLeay::BIO_write($self->{rbio},$data);
    }

    sub bio_read {
        my ($self) = @_;
        return Net::SSLeay::BIO_read($self->{wbio});
    }

    sub _ssl { shift->{ssl} }
    sub _ctx { shift->{ctx} }

    sub _reset {
        my ($self,$group) = @_;
        if ($group) {
            Net::SSLeay::CTX_set1_groups_list($self->{ctx}, $group);
        }
        my $ssl = Net::SSLeay::new($self->{ctx});
        my @bio = (
            Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem()),
            Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem()),
        );
        Net::SSLeay::set_bio($ssl,$bio[0],$bio[1]);
        $self->{ssl} = $ssl;
        $self->{rbio} = $bio[0];
        $self->{wbio} = $bio[1];
    }

    sub _error {
        my ($self,$rv) = @_;
        if ($rv>0) {
            return $rv;
        }
        my $err = Net::SSLeay::get_error($self->{ssl},$rv);
        if ($err == Net::SSLeay::ERROR_WANT_READ()
            || $err == Net::SSLeay::ERROR_WANT_WRITE()) {
            $DEBUG && warn "[$self->{id}] rw:$err\n";
            return;
        }
        $DEBUG && warn "[$self->{id}] ".Net::SSLeay::ERR_error_string($err)."\n";
        return;
    }

}
