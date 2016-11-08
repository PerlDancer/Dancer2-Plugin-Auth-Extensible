use strict;
use warnings;

use Test::More;
use lib 't/lib';

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'one-realm';
}

{
    package TestApp;
    use Test::More;
    use Test::Deep;
    use Test::Fatal;
    use Dancer2;
    use Dancer2::Plugin::Auth::Extensible;

    my $plugin = app->with_plugin('Auth::Extensible');
    my $trap   = dancer_app->logger_engine->trapper;
    my $logs;

    is exception {
        $plugin->create_user(username => 'one-realm', password => 'pwd1');
    },undef,
    "No need to pass realm to create_user since we have only one.";

}

done_testing;
