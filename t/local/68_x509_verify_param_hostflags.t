# Tests for Net::SSLeay::X509_VERIFY_PARAM_get_hostflags

use lib 'inc';

use Net::SSLeay;
use Test::Net::SSLeay qw(initialise_libssl);

plan tests => 5;

initialise_libssl();

SKIP: {
    skip 'X509_VERIFY_PARAM_get_hostflags not available (requires OpenSSL 1.1.0+, not LibreSSL)', 5
        unless exists &Net::SSLeay::X509_VERIFY_PARAM_get_hostflags;

    my $param = Net::SSLeay::X509_VERIFY_PARAM_new();
    ok($param, 'X509_VERIFY_PARAM_new');

    is(
        Net::SSLeay::X509_VERIFY_PARAM_get_hostflags($param),
        0,
        'X509_VERIFY_PARAM_get_hostflags returns 0 by default'
    );

    Net::SSLeay::X509_VERIFY_PARAM_set_hostflags($param, Net::SSLeay::X509_CHECK_FLAG_NO_WILDCARDS());
    is(
        Net::SSLeay::X509_VERIFY_PARAM_get_hostflags($param),
        Net::SSLeay::X509_CHECK_FLAG_NO_WILDCARDS(),
        'X509_VERIFY_PARAM_get_hostflags returns X509_CHECK_FLAG_NO_WILDCARDS after setting it'
    );

    Net::SSLeay::X509_VERIFY_PARAM_set_hostflags($param, 0);
    is(
        Net::SSLeay::X509_VERIFY_PARAM_get_hostflags($param),
        0,
        'X509_VERIFY_PARAM_get_hostflags returns 0 after clearing flags'
    );

    my $combined = Net::SSLeay::X509_CHECK_FLAG_NO_WILDCARDS()
                 | Net::SSLeay::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS();
    Net::SSLeay::X509_VERIFY_PARAM_set_hostflags($param, $combined);
    is(
        Net::SSLeay::X509_VERIFY_PARAM_get_hostflags($param),
        $combined,
        'X509_VERIFY_PARAM_get_hostflags returns combined flags'
    );

    Net::SSLeay::X509_VERIFY_PARAM_free($param);
}
