# Ensure module distribution passes Kwalitee checks

use lib 'inc';

use Test::Net::SSLeay;

use Test::Kwalitee qw(kwalitee_ok);

kwalitee_ok();

done_testing();
