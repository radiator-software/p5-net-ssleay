BEGIN {
    unless ($ENV{RELEASE_TESTING})
    {
	use Test::More;
	plan(skip_all => 'these tests are for only for release candidate testing. Enable with RELEASE_TESTING=1');
    }
}

use Test::Kwalitee;
