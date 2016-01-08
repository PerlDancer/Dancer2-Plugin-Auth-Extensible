use strict;
use warnings;

use Test::More;
use Class::Load 'try_load_class';
use Plack::Test;
use Dancer2::Plugin::Auth::Extensible::Test;

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'provider-database';
    try_load_class('DBD::SQLite')
      or plan skip_all => "DBD::SQLite required to run these tests";
#    try_load_class('Dancer2::Plugin::Database')
#      or plan skip_all =>
#      "Dancer2::Plugin::Database required to run these tests";
}

{
    package TestApp;
    use Path::Tiny;
    use Dancer2;
    use Dancer2::Plugin::Database;
    use Dancer2::Plugin::Auth::Extensible;
    use Dancer2::Plugin::Auth::Extensible::Test::App;

    my $dbh1 = database('database1');
    my $dbh2 = database('database2');
    my $ddl = path('t/database/testapp.ddl');

    $dbh1->do($_)
      for split( /;/,
        join( ';', $ddl->slurp, path('t/database/config1.sql')->slurp ) );

    $dbh2->do($_)
      for split( /;/,
        join( ';', $ddl->slurp, path('t/database/config2.sql')->slurp ) );
}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

test_psgi $app, Dancer2::Plugin::Auth::Extensible::Test::test_the_app_sub();

done_testing;
