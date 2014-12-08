use strict;
use warnings;

use Test::More;
use Plack::Test;
use t::lib::TestSub;

BEGIN {
    $ENV{DANCER_CONFDIR} = 't/lib';
}

{
    package MyApp;
    use Dancer2;
    use t::lib::TestApp;
}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

test_psgi $app, t::lib::TestSub::test_the_app_sub();

done_testing;
