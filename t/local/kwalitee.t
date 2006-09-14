#!perl

use strict;
use warnings;
use Test::More;

eval "use Test::Kwalitee;";
plan skip_all => 'Needs Test::Kwalitee' if $@;
