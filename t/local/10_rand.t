# RAND-related tests

use lib 'inc';

use Net::SSLeay;
use Test::Net::SSLeay;

use File::Spec;

plan tests => 52;

is(Net::SSLeay::RAND_status(), 1, 'RAND_status');
is(Net::SSLeay::RAND_poll(), 1, 'RAND_poll');

# RAND_file_name
my $file_name = Net::SSLeay::RAND_file_name(300);
isnt($file_name, undef, 'RAND_file_name returns defined value');
isnt($file_name, "", "RAND_file_name returns non-empty string: $file_name");

# RAND_load_file
my $binary_file = File::Spec->catfile('t', 'data', 'binary-test.file');
my $binary_file_size = -s $binary_file;
cmp_ok($binary_file_size, '>=', 1000, "Have binary file with good size: $binary_file $binary_file_size");
is(Net::SSLeay::RAND_load_file($binary_file, $binary_file_size), $binary_file_size, 'RAND_load with specific size');
if (Net::SSLeay::constant("LIBRESSL_VERSION_NUMBER"))
{
    # RAND_load_file does nothing on LibreSSL but should return something sane
    cmp_ok(Net::SSLeay::RAND_load_file($binary_file, -1), '>', 0, 'RAND_load with -1 is positive with LibreSSL');
} else {
    is(Net::SSLeay::RAND_load_file($binary_file, -1), $binary_file_size, 'RAND_load with -1 returns file size');
}

test_rand_bytes();

exit(0);

sub test_rand_bytes
{
    my ($ret, $rand_bytes, $rand_length, $rand_expected_length);

    my @rand_lengths = (0, 1, 1024, 65536, 1024**2);

    foreach $rand_expected_length (@rand_lengths)
    {
	$rand_length = $rand_expected_length;
	$ret = Net::SSLeay::RAND_bytes($rand_bytes, $rand_length);
	test_rand_bytes_results('RAND_bytes', $ret, $rand_bytes, $rand_length, $rand_expected_length);
    }

    foreach $rand_expected_length (@rand_lengths)
    {
	$rand_length = $rand_expected_length;
	$ret = Net::SSLeay::RAND_pseudo_bytes($rand_bytes, $rand_length);
	test_rand_bytes_results('RAND_pseudo_bytes', $ret, $rand_bytes, $rand_length, $rand_expected_length);
    }

    if (defined &Net::SSLeay::RAND_priv_bytes)
    {
	foreach $rand_expected_length (@rand_lengths)
	{
	    $rand_length = $rand_expected_length;
	    $ret = Net::SSLeay::RAND_priv_bytes($rand_bytes, $rand_length);
	    test_rand_bytes_results('RAND_priv_bytes', $ret, $rand_bytes, $rand_length, $rand_expected_length);
	}
    } else {
	SKIP : {
	    # Multiplier is the test count in test_rand_bytes_results
	    skip("Do not have Net::SSLeay::RAND_priv_bytes", ((scalar @rand_lengths) * 3));
	};
    }
}

sub test_rand_bytes_results
{
    my ($func, $ret, $rand_bytes, $rand_length, $rand_expected_length) = @_;

    # RAND_bytes functions do not update their rand_length argument, but check for this
    is($ret, 1, "$func: $rand_expected_length return value ok");
    is(length($rand_bytes), $rand_length, "$func: length of rand_bytes and rand_length match");
    is(length($rand_bytes), $rand_expected_length, "$func: length of rand_bytes is expected length $rand_length");
}
