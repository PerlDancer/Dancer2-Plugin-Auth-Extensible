use strict;
use warnings;

use Test::More;
use Dancer2::Plugin::Auth::Extensible::Test;

BEGIN {
    $ENV{DANCER_CONFDIR} = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'provider-config-disable-roles';
}

{
    package TestApp;
    use Dancer2;
    use Dancer2::Plugin::Auth::Extensible::Test::App;
}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

Dancer2::Plugin::Auth::Extensible::Test::testme($app, 'base', 'disable_roles');

done_testing;
