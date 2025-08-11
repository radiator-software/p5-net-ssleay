
# Tests for SSL_CTX_set1_sigalgs_list and related functions

use lib 'inc';

use Net::SSLeay;
use Test::Net::SSLeay qw(initialise_libssl new_ctx);

initialise_libssl();

if (!defined &Net::SSLeay::CTX_set1_sigalgs_list) {
    plan skip_all => "No CTX_set1_sigalgs_list()";
} else {
    plan tests => 16;
}

my $version_num = Net::SSLeay::OPENSSL_VERSION_NUMBER();

my ($ctx, $proto) = new_ctx('TLSv1.2', 'TLSv1.3');
my $ssl = Net::SSLeay::new($ctx);

# '?' in the list means that the algorithm can be ignored if it's not
# implemented
my @tests = (
    # TLSv1.3 list                   # TLSv1.2 list       # components in the list # retval
    ['rsa_pss_rsae_sha256',          'RSA+SHA1',          'valid',                 1],
    ['rsa_pss_rsae_sha256:invalid',  'RSA+SHA1:invalid',  'valid and invalid',     0],
    ['invalid',                      'invalid',           'invalid',               0],
    ['rsa_pss_rsae_sha256:?invalid', 'RSA+SHA1:?invalid', 'valid and ignored',     1],
    );

foreach my $test (@tests)
{
    my $list = $proto eq 'TLSv1.3' ? $test->[0] : $test->[1];

  SKIP: {
      # Support for ignoring a sigalg requires OpenSSL 3.0 and later
      skip "No support for ignoring signature algorithms in " . Net::SSLeay::SSLeay_version(), 4
	  if ($list =~ m/\?/s && $version_num < 0x30300000);
	is(Net::SSLeay::CTX_set1_sigalgs_list       ($ctx, $list), $test->[3], "$proto CTX_set1_sigalgs_list('$list') list is: $test->[2]");
	is(Net::SSLeay::CTX_set1_client_sigalgs_list($ctx, $list), $test->[3], "$proto CTX_set1_client_sigalgs_list('$list') list is: $test->[2]");
	is(Net::SSLeay::set1_sigalgs_list       ($ssl, $list), $test->[3], "$proto set1_sigalgs_list('$list') list is: $test->[2]");
	is(Net::SSLeay::set1_client_sigalgs_list($ssl, $list), $test->[3], "$proto set1_client_sigalgs_list('$list') list is: $test->[2]");
  }
}
